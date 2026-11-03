package rules

import (
	"fmt"
	"strconv"
	"strings"

	"medaudit/internal/facts"
)

// 业务接口越权规则（M4-4）：按检查类型各立一条，不用一个笼统通过项包住整个引擎。
// 事实契约见 internal/apiaudit/facts.go（ToFacts）：探针事实 Source=api.audit，
// 正向对照事实 Source=api.control。评估语义：
//   - FAIL 是引擎已拿到确切证据的结论（水平越权要求 canary 命中；2xx 无 canary
//     仍为 UNKNOWN，不由转换器升级）；FAIL 事实存在时规则直接 FAIL（对照不推翻）。
//   - 负向探针与正向对照必须区分：探针事实中 PASS+2xx 恒为授权方自己的成功
//     （管理员达管理端点、已认证用户达需认证端点、属主自访问、管理跨主体），
//     只证明端点存在，不证明“负向身份已被拒”；负向探针通过恒为拒答（4xx）。
//     只配置授权方身份时，探针全是对照、负向覆盖为零 → UNKNOWN，绝不判 PASS。
//   - PASS 要求每个负向通过探针都有同端点正向对照（对照事实 control 与 Subject 均匹配）：
//     拒答可能是端点不存在的 404，而非真实访问控制；无对照的负向通过一律 UNKNOWN。
//   - 未运行项是覆盖缺口：只读策略跳过的写方法、非公开端点的重放未探测，
//     只要存在即 UNKNOWN（有明确 FAIL 时仍 FAIL）；公开端点重放跳过是合法省略，
//     不算缺口。全部未运行 → UNKNOWN；无此类探针（且无对照探针）→ NOT_APPLICABLE
//     （该接口无此期望的端点，或未配置此类检查）；有对照探针但无负向探针 →
//     UNKNOWN（端点存在但该身份从未被测，如仅有属主自访问而无跨主体探针）。
//     全部探针均为公开端点重放跳过时 → NOT_APPLICABLE：纯公开端点无需重放探测，
//     本规则不适用（不是通过，也不是未确认）。
//   - 未认证与垂直越权的分流：直接探针按 anonymous 属性分流
//     （true → 未认证规则的匿名证据；false → 已认证身份证据，不属未认证规则，
//     管理员端点的 false FAIL 归垂直规则；缺失 → 老报告无法归属，未认证规则不认领）。
//     无匿名身份或老报告缺标记时，未认证规则的匿名覆盖为零 → UNKNOWN（不误判 PASS）。
//   - 覆盖按端点核对：每个适用端点须至少一条已确认负向探针；A 端点完成不能掩盖
//     B 端点的缺口（B 只有正向响应、或只有非本规则身份的探测时，B 未覆盖 → UNKNOWN）。
//     仅当某端点的探针全部为合法省略（公开端点重放跳过）时，该端点不算缺口。

// apiProbeFacts 本规则的探针事实（Source=api.audit 且 match）。
func apiProbeFacts(ctx *EvalContext, match func(facts.Fact) bool) []facts.Fact {
	var out []facts.Fact
	for _, f := range ctx.ByKind[facts.FactAPICheck] {
		if f.Source == "api.audit" && match(f) {
			out = append(out, f)
		}
	}
	return out
}

// apiHasControl 同端点正向对照是否存在（control 种类之一、Subject 相同）。
func apiHasControl(ctx *EvalContext, endpoint string, kinds ...string) bool {
	for _, f := range ctx.ByKind[facts.FactAPICheck] {
		if f.Source != "api.control" || f.Subject != endpoint || f.Attributes["outcome"] != "pass" {
			continue
		}
		for _, k := range kinds {
			if f.Attributes["control"] == k {
				return true
			}
		}
	}
	return false
}

// apiIsControlProbe 探针事实是否为正向对照（授权方自己的成功）：
// 引擎判定保证负向探针通过恒为拒答（4xx），授权方成功恒为 2xx；
// 故 PASS+2xx 只证明端点存在，不计入负向覆盖。FAIL 与 UNKNOWN 不受此影响
// （引擎的 FAIL 只来自负向身份 2xx，授权方被拒恒为 UNKNOWN）。
func apiIsControlProbe(f facts.Fact) bool {
	if f.Attributes["outcome"] != "PASS" {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(f.Attributes["status"]))
	return err == nil && n >= 200 && n < 300
}

// apiIsLegitReplaySkip 重放的合法省略：公开端点无需会话，失效会话被接受
// 不是漏洞，跳过不算覆盖缺口（其余 NOT_RUN 均为缺口）。
func apiIsLegitReplaySkip(f facts.Fact) bool {
	return strings.HasPrefix(f.Attributes["probe"], "replay:") &&
		f.Attributes["expectation"] == "public"
}

// apiProbeClass 负向探针的归属分类（门控用）：已确认负向、无法归属、
// 已确认不属于本规则。无法归属（如老报告缺身份标记）不计入覆盖，
// 但其存在使结论无法确认；已确认不属于本规则的不计入覆盖，
// 所在端点仍按端点覆盖核对（见下）。
type apiProbeClass int

const (
	// apiProbeNegative 已确认的负向探针（计入覆盖与 FAIL 归属）。
	apiProbeNegative apiProbeClass = iota
	// apiProbeUnattributable 无法归属的探针：不计入覆盖，但结论无法确认。
	apiProbeUnattributable
	// apiProbeExcluded 已确认不属于本规则的探针：不计入覆盖。
	apiProbeExcluded
)

// apiRuleEvidence 通用门控：match 选探针事实（规则适用范围），controls 为负向通过
// 所需的对照种类，classify 为空时全部非对照探针均为已确认负向探针。
// 覆盖按端点核对：每个适用端点须至少一条已确认负向探针，否则为覆盖缺口——
// A 端点完成不能掩盖 B 端点的缺口（B 只有正向响应时 B 未覆盖）。
// 仅当全部探针均为合法省略（公开端点重放跳过）时，该端点不算缺口。
func apiRuleEvidence(match func(facts.Fact) bool, controls []string, classify func(facts.Fact) apiProbeClass) EvidenceCheck {
	return func(ctx *EvalContext) (EvidenceStatus, string) {
		probes := apiProbeFacts(ctx, match)
		if len(probes) == 0 {
			return EvidenceNotApplicable, "本报告无此类探针（该接口无此期望的端点或未配置此类检查）"
		}
		// 负向探针 = 除正向对照外的全部探针；对照探针只证明端点存在。
		var executed, fails, unknowns, unattributed, gaps []facts.Fact
		legitSkips := 0
		endpointNegative := map[string]bool{}
		endpointHasEffectiveProbe := map[string]bool{}
		for _, f := range probes {
			ep := f.Subject
			if apiIsControlProbe(f) {
				// 正向对照探针只证明端点存在：端点有实际探测但无负向覆盖时仍算缺口。
				endpointHasEffectiveProbe[ep] = true
				continue
			}
			class := apiProbeNegative
			if classify != nil {
				class = classify(f)
			}
			switch class {
			case apiProbeExcluded:
				endpointHasEffectiveProbe[ep] = true
			case apiProbeUnattributable:
				endpointHasEffectiveProbe[ep] = true
				unattributed = append(unattributed, f)
			case apiProbeNegative:
				if f.Attributes["outcome"] == "NOT_RUN" && apiIsLegitReplaySkip(f) {
					// 合法省略：既不计覆盖，也不算缺口（公开端点无需重放探测）。
					legitSkips++
					continue
				}
				endpointHasEffectiveProbe[ep] = true
				endpointNegative[ep] = true
				switch f.Attributes["outcome"] {
				case "NOT_RUN":
					gaps = append(gaps, f)
				case "FAIL":
					fails = append(fails, f)
				case "PASS":
					executed = append(executed, f)
				default: // UNKNOWN 与一切未识别结论都不当作通过
					unknowns = append(unknowns, f)
				}
			}
		}
		var uncovered []string
		for ep := range endpointHasEffectiveProbe {
			if !endpointNegative[ep] {
				uncovered = append(uncovered, ep)
			}
		}
		// 全部探针均为公开端点重放跳过 → 不适用（纯公开端点无需重放探测，
		// 不是通过，也不是未确认）。
		if legitSkips > 0 && legitSkips == len(probes) {
			return EvidenceNotApplicable, "全部探针均为公开端点重放跳过（合法省略），本规则不适用"
		}
		// 可归属 FAIL 存在 → 直接 Ready（check 命中即 FAIL）。
		if len(fails) > 0 {
			return EvidenceReady, ""
		}
		if len(fails) == 0 && len(unknowns) == 0 && len(executed) == 0 && len(gaps) == 0 &&
			len(unattributed) == 0 && len(uncovered) == 0 {
			return EvidenceMissing, "此类探针全部未运行（写方法只读策略下跳过，或未配置）"
		}
		// 无法归属、结论不明、未运行缺口、端点未覆盖、负向通过缺对照 → Partial：
		// check 有命中则 FAIL，无命中则 UNKNOWN，绝不误判 PASS。
		if len(unattributed) > 0 {
			return EvidencePartial, "存在无法归属本规则的探针（老报告缺身份标记或未配置匿名身份），无法单独确认"
		}
		if len(unknowns) > 0 {
			return EvidencePartial, "部分探针结论不明，无法确认通过"
		}
		if len(gaps) > 0 {
			return EvidencePartial, "部分适用端点未运行（只读策略跳过写方法或重放目标未探测），无法确认通过"
		}
		if len(uncovered) > 0 {
			return EvidencePartial, fmt.Sprintf("部分适用端点无负向探针（仅有正向响应或非本规则身份探测），无法确认通过：%s", strings.Join(uncovered, "、"))
		}
		for _, f := range executed {
			if !apiHasControl(ctx, f.Subject, controls...) {
				return EvidencePartial, fmt.Sprintf("端点 %s 的通过缺少同端点正向对照（拒答可能是端点不存在）", f.Subject)
			}
		}
		return EvidenceReady, ""
	}
}

// apiAnonClassify 未认证规则的探针归属：只认 anonymous=true 为匿名证据；
// anonymous=false 是已认证身份的探测（归垂直规则，不属未认证规则）；
// 缺失是老报告（无匿名身份清单），无法归属，不得认领为匿名证据。
func apiAnonClassify(f facts.Fact) apiProbeClass {
	switch f.Attributes["anonymous"] {
	case "true":
		return apiProbeNegative
	case "false":
		return apiProbeExcluded
	default:
		return apiProbeUnattributable
	}
}

// apiFailHits 本规则的 FAIL 命中（Subject=端点，Evidence=事实 ID）。
func apiFailHits(ctx *EvalContext, match func(facts.Fact) bool) []CheckHit {
	var hits []CheckHit
	for _, f := range apiProbeFacts(ctx, match) {
		if f.Attributes["outcome"] != "FAIL" {
			continue
		}
		hits = append(hits, CheckHit{
			Subject:  f.Subject,
			Detail:   fmt.Sprintf("%s：身份 %s 返回 HTTP %s，%s", f.Subject, f.Attributes["identity"], f.Attributes["status"], f.Attributes["detail"]),
			Evidence: []string{f.FactID},
		})
	}
	return hits
}

// 写方法只读策略的 NOT_RUN 事实（probe=readonly-policy）按期望归属各规则：
// 端点存在但未被探测，结论应为 UNKNOWN（未运行），而非 NOT_APPLICABLE。
// 未认证规则的适用范围是全部受保护端点（需认证 + 管理员）：管理员端点即使
// 只有已认证身份的探针也进入范围——匿名从未被测时结论为 UNKNOWN（端点未覆盖），
// 而非 NOT_APPLICABLE；归属由 apiAnonClassify 再分流（true 为匿名证据，
// false 已确认不属本规则，缺失无法归属）。
func apiAnonMatch(f facts.Fact) bool {
	probe := f.Attributes["probe"]
	if probe != "direct" && probe != "readonly-policy" {
		return false
	}
	switch f.Attributes["expectation"] {
	case "authenticated", "admin_only":
		return true
	}
	return false
}

// apiAnonHit 未认证规则的 FAIL 归属：只认 anonymous=true 的探针 2xx。
// 已认证身份的 2xx 不是匿名越权（需认证端点的已认证成功本就是合法访问；
// 管理员端点的已认证成功归垂直规则）；缺失标记的老报告 FAIL 无法归属，
// 不认领（门控 Partial → UNKNOWN）。
func apiAnonHit(f facts.Fact) bool {
	return f.Attributes["outcome"] == "FAIL" && f.Attributes["anonymous"] == "true"
}

func apiVerticalMatch(f facts.Fact) bool {
	probe := f.Attributes["probe"]
	return (probe == "direct" || probe == "readonly-policy") &&
		f.Attributes["expectation"] == "admin_only" &&
		f.Attributes["anonymous"] != "true"
}

func apiHorizontalMatch(f facts.Fact) bool {
	// 属主自访问探针（self）计入本规则范围：它是端点存在的对照；
	// 仅有自访问而无跨主体探针时，门控应判 UNKNOWN 而非不适用。
	return strings.HasPrefix(f.Attributes["probe"], "cross-owner:") ||
		(f.Attributes["probe"] == "self" && f.Attributes["expectation"] == "owner_or_admin") ||
		(f.Attributes["probe"] == "readonly-policy" && f.Attributes["expectation"] == "owner_or_admin")
}

func apiReplayMatch(f facts.Fact) bool {
	return strings.HasPrefix(f.Attributes["probe"], "replay:")
}

var apiBuiltinRules = []builtinRule{
	{
		spec: RuleSpec{
			ID: "api.anon_protected_access", Version: "3",
			Name:   "未认证访问受保护接口",
			Target: facts.TargetAPI,
			Description: "匿名身份可达需认证或管理员端点（直接探针 2xx）。匿名证据只认报告中" +
				"明确标记 anonymous=true 的探针：普通用户的拒答不得充当匿名探针，缺匿名探针" +
				"或老报告缺身份标记时匿名从未被证实，不判通过；管理员端点的已认证身份 2xx " +
				"归垂直越权规则。覆盖按端点核对：每个适用端点须有匿名负向探针，仅有正向响应" +
				"的端点是缺口。通过要求每个负向通过探针（匿名拒答）都有同端点正向对照" +
				"（已认证或管理员 2xx），否则拒答可能是端点不存在，不判通过。",
			Requires:    []facts.FactKind{facts.FactAPICheck},
			Evidence:    apiRuleEvidence(apiAnonMatch, []string{"authed_reachable", "admin_reachable"}, apiAnonClassify),
			Risk:        RiskHigh,
			Remediation: "给受保护接口补鉴权：未携带有效会话一律拒绝，并复测匿名探针。",
		},
		check: func(c *EvalContext) []CheckHit {
			return apiFailHits(c, func(f facts.Fact) bool { return apiAnonMatch(f) && apiAnonHit(f) })
		},
	},
	{
		spec: RuleSpec{
			ID: "api.user_admin_access", Version: "3",
			Name:   "普通身份访问管理员接口",
			Target: facts.TargetAPI,
			Description: "非管理员身份（含匿名，老报告无法区分时亦归此）可达管理员端点（直接探针 2xx，" +
				"垂直越权）。通过要求每个负向通过探针（非管理员拒答）都有同端点管理员正向对照" +
				"（管理员 2xx），否则拒答可能是端点不存在，不判通过；只配置管理员身份而无" +
				"非管理员探针时，非管理员从未被测，不判通过。",
			Requires:    []facts.FactKind{facts.FactAPICheck},
			Evidence:    apiRuleEvidence(apiVerticalMatch, []string{"admin_reachable"}, nil),
			Risk:        RiskHigh,
			Remediation: "给管理员端点补角色校验：非管理员一律拒绝，并复测普通身份与匿名探针。",
		},
		check: func(c *EvalContext) []CheckHit {
			return apiFailHits(c, apiVerticalMatch)
		},
	},
	{
		spec: RuleSpec{
			ID: "api.cross_owner_access", Version: "3",
			Name:   "跨所有者访问",
			Target: facts.TargetAPI,
			Description: "非管理员身份跨主体读到他人的私有数据（跨主体探针 2xx 且命中属主 canary，" +
				"水平越权）。2xx 但未命中 canary 仍为证据不足（可能是脱敏或共享数据），不判 FAIL 也不判 PASS。" +
				"通过要求每个负向通过探针（跨主体拒答）都有同端点属主自访问正向对照（属主 2xx），" +
				"否则拒答可能是端点不存在；仅有属主自访问而无跨主体探针时，跨主体从未被测，不判通过。",
			Requires:    []facts.FactKind{facts.FactAPICheck},
			Evidence:    apiRuleEvidence(apiHorizontalMatch, []string{"self_reachable"}, nil),
			Risk:        RiskHigh,
			Remediation: "给资源端点补属主校验：只能读自有资源，管理员除外；并复测跨主体探针。",
		},
		check: func(c *EvalContext) []CheckHit {
			return apiFailHits(c, apiHorizontalMatch)
		},
	},
	{
		spec: RuleSpec{
			ID: "api.invalidated_session_replay", Version: "4",
			Name:   "凭据失效后重放",
			Target: facts.TargetAPI,
			Description: "已失效会话（登出、过期、改密、吊销后捕获的凭证）重放仍被接受（重放探针 2xx）。" +
				"通过要求每个负向通过探针（重放拒答）都有同端点差分正向对照（差分阶段该端点有 2xx，" +
				"证明端点存在），否则拒答可能是端点不存在，不判通过；未运行的重放目标（非公开端点）" +
				"是覆盖缺口，不判通过；公开端点重放跳过不算缺口。重放会话的有效性由操作员在配置中声明，" +
				"本规则不验证该声明本身。",
			Requires:    []facts.FactKind{facts.FactAPICheck},
			Evidence:    apiRuleEvidence(apiReplayMatch, []string{"endpoint_reachable"}, nil),
			Risk:        RiskHigh,
			Remediation: "确保登出、过期、改密、吊销真实失效服务端会话（删会话、轮换密钥、缩短有效期），并复测重放。",
		},
		check: func(c *EvalContext) []CheckHit {
			return apiFailHits(c, apiReplayMatch)
		},
	},
}
