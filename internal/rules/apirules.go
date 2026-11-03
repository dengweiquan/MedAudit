package rules

import (
	"fmt"
	"strings"

	"medaudit/internal/facts"
)

// 业务接口越权规则（M4-4）：按检查类型各立一条，不用一个笼统通过项包住整个引擎。
// 事实契约见 internal/apiaudit/facts.go（ToFacts）：探针事实 Source=api.audit，
// 正向对照事实 Source=api.control。评估语义：
//   - FAIL 是引擎已拿到确切证据的结论（水平越权要求 canary 命中；2xx 无 canary
//     仍为 UNKNOWN，不由转换器升级）；FAIL 事实存在时规则直接 FAIL（对照不推翻）。
//   - PASS 要求每个 PASS 探针都有同端点正向对照（对照事实 control 与 Subject 均匹配）：
//     拒答可能是端点不存在的 404，而非真实访问控制；无对照的 PASS 一律 UNKNOWN。
//   - 全部 NOT_RUN（写方法只读策略）→ UNKNOWN；无此类探针 → NOT_APPLICABLE
//     （该接口无此期望的端点，或未配置此类检查）。
//   - 未认证与垂直越权的分流：管理员端点直接探针按 anonymous 属性分流
//     （true → 未认证规则；false 或缺失 → 垂直规则；匿名本就是非管理员子集，
//     老报告缺失时归垂直不算误报）。老报告的管理员端点 FAIL 若无法确认是否匿名，
//     未认证规则返回 Partial：有可归属 FAIL 时仍 FAIL，否则 UNKNOWN（不误判 PASS）。

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

// apiRuleEvidence 通用门控：match 选探针事实，controls 为 PASS 所需的对照种类。
// unattributableFail 为真表示存在无法归属本规则的 FAIL 事实（仅未认证规则用）：
// 此时不直接 Ready，若 check 无可归属命中则落 UNKNOWN。
func apiRuleEvidence(match func(facts.Fact) bool, controls []string, unattributableFail func(facts.Fact) bool) EvidenceCheck {
	return func(ctx *EvalContext) (EvidenceStatus, string) {
		probes := apiProbeFacts(ctx, match)
		if len(probes) == 0 {
			return EvidenceNotApplicable, "本报告无此类探针（该接口无此期望的端点或未配置此类检查）"
		}
		var executed, fails, unknowns, unattributed []facts.Fact
		for _, f := range probes {
			switch f.Attributes["outcome"] {
			case "NOT_RUN":
			case "FAIL":
				fails = append(fails, f)
				if unattributableFail != nil && unattributableFail(f) {
					unattributed = append(unattributed, f)
				}
			case "PASS":
				executed = append(executed, f)
			default: // UNKNOWN 与一切未识别结论都不当作通过
				unknowns = append(unknowns, f)
			}
		}
		// 可归属 FAIL 存在 → 直接 Ready（check 命中即 FAIL）。
		if len(fails) > len(unattributed) {
			return EvidenceReady, ""
		}
		if len(fails) == 0 && len(unknowns) == 0 && len(executed) == 0 {
			return EvidenceMissing, "此类探针全部未运行（写方法只读策略下跳过，或未配置）"
		}
		// 仅有无法归属的 FAIL、或有 UNKNOWN、或 PASS 缺对照 → Partial：
		// check 有命中则 FAIL，无命中则 UNKNOWN，绝不误判 PASS。
		if len(unattributed) > 0 {
			return EvidencePartial, "存在无法确认是否匿名的管理员端点 FAIL，本规则无法单独确认"
		}
		if len(unknowns) > 0 {
			return EvidencePartial, "部分探针结论不明，无法确认通过"
		}
		for _, f := range executed {
			if !apiHasControl(ctx, f.Subject, controls...) {
				return EvidencePartial, fmt.Sprintf("端点 %s 的通过缺少同端点正向对照（拒答可能是端点不存在）", f.Subject)
			}
		}
		return EvidenceReady, ""
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
func apiAnonMatch(f facts.Fact) bool {
	probe := f.Attributes["probe"]
	if probe != "direct" && probe != "readonly-policy" {
		return false
	}
	switch f.Attributes["expectation"] {
	case "authenticated":
		return true
	case "admin_only":
		return f.Attributes["anonymous"] != "false"
	}
	return false
}

func apiAnonHit(f facts.Fact) bool {
	if f.Attributes["outcome"] != "FAIL" {
		return false
	}
	if f.Attributes["expectation"] == "authenticated" {
		return true
	}
	return f.Attributes["expectation"] == "admin_only" && f.Attributes["anonymous"] == "true"
}

func apiAnonUnattributed(f facts.Fact) bool {
	return f.Attributes["expectation"] == "admin_only" && f.Attributes["anonymous"] == ""
}

func apiVerticalMatch(f facts.Fact) bool {
	probe := f.Attributes["probe"]
	return (probe == "direct" || probe == "readonly-policy") &&
		f.Attributes["expectation"] == "admin_only" &&
		f.Attributes["anonymous"] != "true"
}

func apiHorizontalMatch(f facts.Fact) bool {
	return strings.HasPrefix(f.Attributes["probe"], "cross-owner:") ||
		(f.Attributes["probe"] == "readonly-policy" && f.Attributes["expectation"] == "owner_or_admin")
}

func apiReplayMatch(f facts.Fact) bool {
	return strings.HasPrefix(f.Attributes["probe"], "replay:")
}

var apiBuiltinRules = []builtinRule{
	{
		spec: RuleSpec{
			ID: "api.anon_protected_access", Version: "1",
			Name:   "未认证访问受保护接口",
			Target: facts.TargetAPI,
			Description: "匿名身份可达需认证或管理员端点（直接探针 2xx）。需认证端点的匿名 2xx " +
				"本身即属匿名；管理员端点的匿名 2xx 按报告的匿名身份清单分流（清单缺失的老报告不认领，" +
				"只归垂直越权规则）。通过要求每个通过探针都有同端点正向对照（已认证或管理员 2xx），" +
				"否则拒答可能是端点不存在，不判通过。",
			Requires:    []facts.FactKind{facts.FactAPICheck},
			Evidence:    apiRuleEvidence(apiAnonMatch, []string{"authed_reachable", "admin_reachable"}, apiAnonUnattributed),
			Risk:        RiskHigh,
			Remediation: "给受保护接口补鉴权：未携带有效会话一律拒绝，并复测匿名探针。",
		},
		check: func(c *EvalContext) []CheckHit {
			return apiFailHits(c, func(f facts.Fact) bool { return apiAnonMatch(f) && apiAnonHit(f) })
		},
	},
	{
		spec: RuleSpec{
			ID: "api.user_admin_access", Version: "1",
			Name:   "普通身份访问管理员接口",
			Target: facts.TargetAPI,
			Description: "非管理员身份（含匿名，老报告无法区分时亦归此）可达管理员端点（直接探针 2xx，" +
				"垂直越权）。通过要求每个通过探针都有同端点管理员正向对照（管理员 2xx），" +
				"否则拒答可能是端点不存在，不判通过。",
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
			ID: "api.cross_owner_access", Version: "1",
			Name:   "跨所有者访问",
			Target: facts.TargetAPI,
			Description: "非管理员身份跨主体读到他人的私有数据（跨主体探针 2xx 且命中属主 canary，" +
				"水平越权）。2xx 但未命中 canary 仍为证据不足（可能是脱敏或共享数据），不判 FAIL 也不判 PASS。" +
				"通过要求每个通过探针都有同端点属主自访问正向对照（属主 2xx），否则拒答可能是端点不存在。",
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
			ID: "api.invalidated_session_replay", Version: "1",
			Name:   "凭据失效后重放",
			Target: facts.TargetAPI,
			Description: "已失效会话（登出、过期、改密、吊销后捕获的凭证）重放仍被接受（重放探针 2xx）。" +
				"通过要求每个通过探针都有同端点差分正向对照（差分阶段该端点有 2xx，证明端点存在），" +
				"否则拒答可能是端点不存在，不判通过。重放会话的有效性由操作员在配置中声明，" +
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
