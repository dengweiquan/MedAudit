package apiaudit

import (
	"fmt"
	"strings"

	"medaudit/internal/facts"
)

// ToFacts 把一次 API 审计报告转换为规则引擎可评估的事实（合成包原料）。
//
// 事实契约（规则 internal/rules/apirules.go 依赖，改动需同步）：
//   - Kind 均为 api_check，Status 均为 observed，Source 为 api.audit（探针事实）
//     或 api.control（正向对照事实），Subject 为端点模板（如 "GET /api/users/{id}"）。
//   - 探针事实属性：probe（direct | self | cross-owner:<名> | replay:<失效条件> |
//     readonly-policy）、expectation（public | authenticated | admin_only |
//     owner_or_admin）、identity、outcome（PASS | FAIL | UNKNOWN | NOT_RUN）、
//     status（HTTP 状态码，0 = 传输错误）、detail（引擎原文，经脱敏）。
//   - 管理员端点直接探针另带 anonymous 属性：true（匿名身份）、false（已认证身份）、
//     缺失（老报告无匿名身份清单，无法区分）。合规规则据此分流：
//     anonymous=true 的 FAIL 归未认证规则；false 或缺失的 FAIL 归垂直越权规则
//     （匿名本就是非管理员的子集，归垂直不算误报；缺失时未认证规则不认领）。
//   - 正向对照事实（control 属性）由同报告的差分 2xx 派生，不新增探针：
//     public_reachable（公开端点匿名 2xx）、authed_reachable（需认证端点已认证 2xx）、
//     admin_reachable（管理员端点管理员 2xx：直接探针 PASS 且状态 2xx，非管理员
//     拒答的 PASS 状态为 4xx，故状态码即可区分，无需角色元数据）、
//     self_reachable（属主自访问 2xx）、endpoint_reachable（重放端点在差分阶段
//     有任意 2xx）。对照事实只证明“端点存在且可达”，不证明越权结论：
//     规则的 PASS 结论要求每个 PASS 探针都有同端点对照，否则为 UNKNOWN
//     （拒答可能是端点不存在的 404，而非真实访问控制）。
//   - 引擎结论原样映射：FAIL 只在引擎已拿到确切证据时出现（水平越权要求 canary
//     命中，2xx 无 canary 仍为 UNKNOWN）；转换器不把 UNKNOWN 升级为 FAIL 或 PASS，
//     不把 NOT_RUN（写方法只读策略）当作通过。
func ToFacts(rep *Report) []facts.Fact {
	if rep == nil {
		return nil
	}
	anon := map[string]bool{}
	for _, n := range rep.AnonymousIdentities {
		anon[n] = true
	}
	knownAnon := len(rep.AnonymousIdentities) > 0
	var out []facts.Fact
	add := func(subject, source string, attrs map[string]string) {
		out = append(out, facts.Fact{
			FactID:     fmt.Sprintf("api-%d", len(out)+1),
			Kind:       facts.FactAPICheck,
			Subject:    subject,
			Status:     facts.StatusObserved,
			Source:     source,
			Attributes: attrs,
		})
	}
	for _, c := range rep.Checks {
		attrs := map[string]string{
			"probe":       c.Probe,
			"expectation": string(c.Expectation),
			"identity":    c.Identity,
			"outcome":     string(c.Conclusion),
			"status":      fmt.Sprintf("%d", c.Status),
			"detail":      facts.RedactSecrets(c.Detail),
		}
		// 管理员端点直接探针的匿名标记（仅新报告可区分）。
		if c.Probe == "direct" && c.Expectation == AccessAdminOnly && knownAnon {
			if anon[c.Identity] {
				attrs["anonymous"] = "true"
			} else {
				attrs["anonymous"] = "false"
			}
		}
		add(c.Endpoint, "api.audit", attrs)
		// 正向对照派生：只有 2xx 的 PASS 才证明端点存在。
		if c.Conclusion == ConclPass && is2xx(c.Status) {
			var control string
			switch {
			case c.Expectation == AccessPublic && c.Probe == "direct":
				control = "public_reachable"
			case c.Expectation == AccessAuthenticated && c.Probe == "direct":
				control = "authed_reachable"
			case c.Expectation == AccessAdminOnly && c.Probe == "direct":
				control = "admin_reachable"
			case c.Expectation == AccessOwnerOrAdmin && c.Probe == "self":
				control = "self_reachable"
			}
			if control != "" {
				add(c.Endpoint, "api.control", map[string]string{
					"control":  control,
					"outcome":  "pass",
					"identity": c.Identity,
				})
			}
			// 重放对照：差分阶段任一 2xx 都证明该端点存在（重放 PASS 的前提）。
			// 重放探针本身不产生对照（其 2xx 是 FAIL，拒答是 4xx，皆非 PASS 2xx）。
			if !strings.HasPrefix(c.Probe, "replay:") {
				add(c.Endpoint, "api.control", map[string]string{
					"control":  "endpoint_reachable",
					"outcome":  "pass",
					"identity": c.Identity,
				})
			}
		}
	}
	return out
}
