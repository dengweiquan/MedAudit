package rules

import (
	"testing"

	"medaudit/internal/facts"
)

// apiFact 构造一条 api_check 事实：source=api.audit（探针）或 api.control（对照）。
func apiFact(id, endpoint, source string, attrs map[string]string) facts.Fact {
	return facts.Fact{FactID: id, Kind: facts.FactAPICheck, Subject: endpoint,
		Status: facts.StatusObserved, Source: source, Attributes: attrs}
}

func apiProbe(id, endpoint, probe, expectation, identity, outcome string, status string) facts.Fact {
	attrs := map[string]string{"probe": probe, "expectation": expectation,
		"identity": identity, "outcome": outcome, "status": status, "detail": "test"}
	return apiFact(id, endpoint, "api.audit", attrs)
}

func apiProbeAnon(id, endpoint, probe, expectation, identity, outcome, status, anon string) facts.Fact {
	f := apiProbe(id, endpoint, probe, expectation, identity, outcome, status)
	if anon != "" {
		f.Attributes["anonymous"] = anon
	}
	return f
}

func apiControl(id, endpoint, control string) facts.Fact {
	return apiFact(id, endpoint, "api.control", map[string]string{
		"control": control, "outcome": "pass", "identity": "ctl"})
}

func apiBundle(fs ...facts.Fact) *facts.FactBundle {
	return &facts.FactBundle{
		Collector:  facts.CollectorInfo{Name: "apiaudit", Adapter: facts.TargetAPI},
		Scope:      facts.Scope{HospitalID: "h1", AssetID: "a1", TargetType: facts.TargetAPI},
		Identities: facts.Identities{CollectorIdentity: "apiaudit", TargetIdentity: "http://x"},
		Facts:      fs,
	}
}

func apiConclusions(t *testing.T, b *facts.FactBundle) map[string]facts.Conclusion {
	t.Helper()
	out := map[string]facts.Conclusion{}
	for _, r := range DefaultRegistry().Evaluate(b, &Baseline{}) {
		switch r.RuleID {
		case "api.anon_protected_access", "api.user_admin_access",
			"api.cross_owner_access", "api.invalidated_session_replay":
			out[r.RuleID] = r.Conclusion
		}
	}
	if len(out) != 4 {
		t.Fatalf("want 4 api rules, got %v", out)
	}
	return out
}

func expectAPI(t *testing.T, b *facts.FactBundle, want map[string]facts.Conclusion) {
	t.Helper()
	got := apiConclusions(t, b)
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s: want %s, got %s", id, w, got[id])
		}
	}
}

// 四类违规齐全 → 四规则全 FAIL（对照不推翻已证实的 FAIL）。
func TestAPIRulesAllFail(t *testing.T) {
	b := apiBundle(
		apiProbeAnon("f1", "GET /api/profile", "direct", "authenticated", "anon", "FAIL", "200", "true"),
		apiProbeAnon("f2", "GET /api/admin/users", "direct", "admin_only", "alice", "FAIL", "200", "false"),
		apiProbe("f3", "GET /api/users/{id}", "cross-owner:alice", "owner_or_admin", "bob", "FAIL", "200"),
		apiProbe("f4", "GET /api/me", "replay:logged_out", "authenticated", "alice-logged-out", "FAIL", "200"),
	)
	expectAPI(t, b, map[string]facts.Conclusion{
		"api.anon_protected_access":      facts.ConclusionFail,
		"api.user_admin_access":          facts.ConclusionFail,
		"api.cross_owner_access":         facts.ConclusionFail,
		"api.invalidated_session_replay": facts.ConclusionFail,
	})
}

// 全通过且每端点有对照 → 全 PASS。
func TestAPIRulesAllPassWithControls(t *testing.T) {
	b := apiBundle(
		apiProbeAnon("f1", "GET /api/profile", "direct", "authenticated", "anon", "PASS", "403", "true"),
		apiProbeAnon("f2", "GET /api/profile", "direct", "authenticated", "alice", "PASS", "200", "false"),
		apiControl("c1", "GET /api/profile", "authed_reachable"),
		apiProbeAnon("f3", "GET /api/admin/users", "direct", "admin_only", "root", "PASS", "200", "false"),
		apiProbeAnon("f4", "GET /api/admin/users", "direct", "admin_only", "alice", "PASS", "403", "false"),
		apiProbeAnon("f4b", "GET /api/admin/users", "direct", "admin_only", "anon", "PASS", "401", "true"),
		apiControl("c2", "GET /api/admin/users", "admin_reachable"),
		apiProbe("f5", "GET /api/users/{id}", "self", "owner_or_admin", "alice", "PASS", "200"),
		apiProbe("f6", "GET /api/users/{id}", "cross-owner:alice", "owner_or_admin", "bob", "PASS", "403"),
		apiControl("c3", "GET /api/users/{id}", "self_reachable"),
		apiProbe("f7", "GET /api/me", "direct", "authenticated", "alice", "PASS", "200"),
		apiProbeAnon("f7b", "GET /api/me", "direct", "authenticated", "anon", "PASS", "401", "true"),
		apiProbe("f8", "GET /api/me", "replay:logged_out", "authenticated", "alice-logged-out", "PASS", "401"),
		apiControl("c4", "GET /api/me", "endpoint_reachable"),
		apiControl("c5", "GET /api/me", "authed_reachable"),
	)
	expectAPI(t, b, map[string]facts.Conclusion{
		"api.anon_protected_access":      facts.ConclusionPass,
		"api.user_admin_access":          facts.ConclusionPass,
		"api.cross_owner_access":         facts.ConclusionPass,
		"api.invalidated_session_replay": facts.ConclusionPass,
	})
}

// 通过但无对照 → 全 UNKNOWN（拒答可能是端点不存在的 404）。
func TestAPIRulesPassWithoutControlsUnknown(t *testing.T) {
	b := apiBundle(
		apiProbeAnon("f1", "GET /api/profile", "direct", "authenticated", "anon", "PASS", "403", "true"),
		apiProbeAnon("f2", "GET /api/admin/users", "direct", "admin_only", "alice", "PASS", "403", "false"),
		apiProbe("f3", "GET /api/users/{id}", "cross-owner:alice", "owner_or_admin", "bob", "PASS", "403"),
		apiProbe("f4", "GET /api/me", "replay:logged_out", "authenticated", "alice-logged-out", "PASS", "401"),
	)
	expectAPI(t, b, map[string]facts.Conclusion{
		"api.anon_protected_access":      facts.ConclusionUnknown,
		"api.user_admin_access":          facts.ConclusionUnknown,
		"api.cross_owner_access":         facts.ConclusionUnknown,
		"api.invalidated_session_replay": facts.ConclusionUnknown,
	})
}

// 只有公开端点 → 四规则全 NOT_APPLICABLE（该接口无受保护面）。
func TestAPIRulesNoProtectedSurfaceNA(t *testing.T) {
	b := apiBundle(
		apiProbe("f1", "GET /api/public/health", "direct", "public", "anon", "PASS", "200"),
	)
	expectAPI(t, b, map[string]facts.Conclusion{
		"api.anon_protected_access":      facts.ConclusionNotApplicable,
		"api.user_admin_access":          facts.ConclusionNotApplicable,
		"api.cross_owner_access":         facts.ConclusionNotApplicable,
		"api.invalidated_session_replay": facts.ConclusionNotApplicable,
	})
}

// 写方法只读策略（NOT_RUN）→ UNKNOWN，不当作通过；管理员端点未探测时
// 未认证与垂直两规则都无法判定（匿名探针同样未运行）。
func TestAPIRulesNotRunUnknown(t *testing.T) {
	b := apiBundle(
		apiProbe("f1", "POST /api/admin/users", "readonly-policy", "admin_only", "-", "NOT_RUN", "0"),
	)
	expectAPI(t, b, map[string]facts.Conclusion{
		"api.anon_protected_access":      facts.ConclusionUnknown,
		"api.user_admin_access":          facts.ConclusionUnknown,
		"api.cross_owner_access":         facts.ConclusionNotApplicable,
		"api.invalidated_session_replay": facts.ConclusionNotApplicable,
	})
}

// 老报告（无 anonymous 属性）的管理员端点 FAIL：垂直 FAIL，未认证 UNKNOWN（不误判 PASS）。
func TestAPIRulesOldReportSplit(t *testing.T) {
	b := apiBundle(
		apiProbeAnon("f1", "GET /api/admin/users", "direct", "admin_only", "someone", "FAIL", "200", ""),
	)
	expectAPI(t, b, map[string]facts.Conclusion{
		"api.anon_protected_access":      facts.ConclusionUnknown,
		"api.user_admin_access":          facts.ConclusionFail,
		"api.cross_owner_access":         facts.ConclusionNotApplicable,
		"api.invalidated_session_replay": facts.ConclusionNotApplicable,
	})
}

// 跨主体 2xx 无 canary（UNKNOWN）+ 其余通过有对照 → 水平 UNKNOWN，其余 PASS。
func TestAPIRulesCrossOwnerUnknownNotFail(t *testing.T) {
	b := apiBundle(
		apiProbe("f1", "GET /api/users/{id}", "self", "owner_or_admin", "alice", "PASS", "200"),
		apiProbe("f2", "GET /api/users/{id}", "cross-owner:alice", "owner_or_admin", "bob", "UNKNOWN", "200"),
		apiControl("c1", "GET /api/users/{id}", "self_reachable"),
	)
	got := apiConclusions(t, b)
	if got["api.cross_owner_access"] != facts.ConclusionUnknown {
		t.Errorf("cross-owner 2xx no canary: want UNKNOWN, got %s", got["api.cross_owner_access"])
	}
}

// 对照错端点不算对照：通过探针的端点无对照 → UNKNOWN。
func TestAPIRulesControlWrongEndpoint(t *testing.T) {
	b := apiBundle(
		apiProbeAnon("f1", "GET /api/admin/users", "direct", "admin_only", "alice", "PASS", "403", "false"),
		apiControl("c1", "GET /api/admin/other", "admin_reachable"),
	)
	got := apiConclusions(t, b)
	if got["api.user_admin_access"] != facts.ConclusionUnknown {
		t.Errorf("control on other endpoint: want UNKNOWN, got %s", got["api.user_admin_access"])
	}
}

// 静态复核回归：正向对照探针（PASS+2xx）不计入负向覆盖。

// 只配置管理员身份：管理端点只有管理员自己的成功探针 → 未认证与垂直规则
// 均 UNKNOWN（匿名与非管理员均从未被测；受保护端点存在，规则适用而非不适用）。
func TestAPIRulesOnlyAdminUnknown(t *testing.T) {
	b := apiBundle(
		apiProbeAnon("f3", "GET /api/admin/users", "direct", "admin_only", "root", "PASS", "200", "false"),
		apiControl("c2", "GET /api/admin/users", "admin_reachable"),
	)
	expectAPI(t, b, map[string]facts.Conclusion{
		"api.anon_protected_access":      facts.ConclusionUnknown,
		"api.user_admin_access":          facts.ConclusionUnknown,
		"api.cross_owner_access":         facts.ConclusionNotApplicable,
		"api.invalidated_session_replay": facts.ConclusionNotApplicable,
	})
}

// 只配置已认证身份：需认证端点只有已认证用户的成功探针 → 未认证规则 UNKNOWN（匿名从未被测）。
func TestAPIRulesOnlyAuthedUnknown(t *testing.T) {
	b := apiBundle(
		apiProbeAnon("f2", "GET /api/profile", "direct", "authenticated", "alice", "PASS", "200", "false"),
		apiControl("c1", "GET /api/profile", "authed_reachable"),
	)
	expectAPI(t, b, map[string]facts.Conclusion{
		"api.anon_protected_access":      facts.ConclusionUnknown,
		"api.user_admin_access":          facts.ConclusionNotApplicable,
		"api.cross_owner_access":         facts.ConclusionNotApplicable,
		"api.invalidated_session_replay": facts.ConclusionNotApplicable,
	})
}

// 负向通过 + 只读策略未运行项 → UNKNOWN（覆盖缺口不得判 PASS）。
func TestAPIRulesPassPlusNotRunUnknown(t *testing.T) {
	b := apiBundle(
		apiProbeAnon("f1", "GET /api/profile", "direct", "authenticated", "anon", "PASS", "403", "true"),
		apiControl("c1", "GET /api/profile", "authed_reachable"),
		apiProbe("f9", "POST /api/profile", "readonly-policy", "authenticated", "-", "NOT_RUN", "0"),
	)
	expectAPI(t, b, map[string]facts.Conclusion{
		"api.anon_protected_access":      facts.ConclusionUnknown,
		"api.user_admin_access":          facts.ConclusionNotApplicable,
		"api.cross_owner_access":         facts.ConclusionNotApplicable,
		"api.invalidated_session_replay": facts.ConclusionNotApplicable,
	})
}

// 仅有属主自访问而无跨主体探针 → 水平规则 UNKNOWN（不得误判不适用）。
func TestAPIRulesOnlySelfUnknown(t *testing.T) {
	b := apiBundle(
		apiProbe("f5", "GET /api/users/{id}", "self", "owner_or_admin", "alice", "PASS", "200"),
		apiControl("c3", "GET /api/users/{id}", "self_reachable"),
	)
	expectAPI(t, b, map[string]facts.Conclusion{
		"api.anon_protected_access":      facts.ConclusionNotApplicable,
		"api.user_admin_access":          facts.ConclusionNotApplicable,
		"api.cross_owner_access":         facts.ConclusionUnknown,
		"api.invalidated_session_replay": facts.ConclusionNotApplicable,
	})
}

// 重放：公开端点跳过是合法省略，不阻塞非公开端点的 PASS。
func TestAPIRulesReplayPublicSkipPass(t *testing.T) {
	b := apiBundle(
		apiProbe("f8", "GET /api/me", "replay:logged_out", "authenticated", "alice-logged-out", "PASS", "401"),
		apiControl("c4", "GET /api/me", "endpoint_reachable"),
		apiProbe("f9", "GET /api/open", "replay:logged_out", "public", "alice-logged-out", "NOT_RUN", "0"),
	)
	expectAPI(t, b, map[string]facts.Conclusion{
		"api.anon_protected_access":      facts.ConclusionNotApplicable,
		"api.user_admin_access":          facts.ConclusionNotApplicable,
		"api.cross_owner_access":         facts.ConclusionNotApplicable,
		"api.invalidated_session_replay": facts.ConclusionPass,
	})
}

// 重放：非公开端点未运行是覆盖缺口 → UNKNOWN。
func TestAPIRulesReplayNonPublicNotRunUnknown(t *testing.T) {
	b := apiBundle(
		apiProbe("f8", "GET /api/me", "replay:logged_out", "authenticated", "alice-logged-out", "PASS", "401"),
		apiControl("c4", "GET /api/me", "endpoint_reachable"),
		apiProbe("f9", "POST /api/me", "replay:logged_out", "authenticated", "alice-logged-out", "NOT_RUN", "0"),
	)
	expectAPI(t, b, map[string]facts.Conclusion{
		"api.anon_protected_access":      facts.ConclusionNotApplicable,
		"api.user_admin_access":          facts.ConclusionNotApplicable,
		"api.cross_owner_access":         facts.ConclusionNotApplicable,
		"api.invalidated_session_replay": facts.ConclusionUnknown,
	})
}

// 静态复核回归二轮：匿名证据须为已确认匿名探针；覆盖按端点核对。

// 只配置 admin 与普通用户、无匿名身份时：普通用户在管理员端点的 403
// 是垂直证据，不是匿名证据 → 未认证 UNKNOWN（不得 PASS），垂直 PASS。
func TestAPIRulesUserDenyNotAnonEvidence(t *testing.T) {
	b := apiBundle(
		apiProbeAnon("f3", "GET /api/admin/users", "direct", "admin_only", "root", "PASS", "200", "false"),
		apiProbeAnon("f4", "GET /api/admin/users", "direct", "admin_only", "alice", "PASS", "403", "false"),
		apiControl("c2", "GET /api/admin/users", "admin_reachable"),
	)
	expectAPI(t, b, map[string]facts.Conclusion{
		"api.anon_protected_access":      facts.ConclusionUnknown,
		"api.user_admin_access":          facts.ConclusionPass,
		"api.cross_owner_access":         facts.ConclusionNotApplicable,
		"api.invalidated_session_replay": facts.ConclusionNotApplicable,
	})
}

// 老报告（缺 anonymous 标记）的管理员端点拒答：未认证无法归属 → UNKNOWN；
// 垂直规则不需区分匿名与普通身份（同为非管理员），有对照即通过。
func TestAPIRulesAnonUnattributablePassUnknown(t *testing.T) {
	b := apiBundle(
		apiProbeAnon("f4", "GET /api/admin/users", "direct", "admin_only", "someone", "PASS", "403", ""),
		apiControl("c2", "GET /api/admin/users", "admin_reachable"),
	)
	expectAPI(t, b, map[string]facts.Conclusion{
		"api.anon_protected_access":      facts.ConclusionUnknown,
		"api.user_admin_access":          facts.ConclusionPass,
		"api.cross_owner_access":         facts.ConclusionNotApplicable,
		"api.invalidated_session_replay": facts.ConclusionNotApplicable,
	})
}

// 按端点覆盖：A 端点负向完成 + 对照齐全，B 端点只有管理员正向响应 →
// B 的缺口不得被 A 掩盖，垂直规则 UNKNOWN（无违规时不判 PASS）；
// 未认证规则同样 UNKNOWN（两端点均无匿名探针）。
func TestAPIRulesPerEndpointCoverage(t *testing.T) {
	b := apiBundle(
		apiProbeAnon("f1", "GET /api/admin/a", "direct", "admin_only", "alice", "PASS", "403", "false"),
		apiControl("c1", "GET /api/admin/a", "admin_reachable"),
		apiProbeAnon("f2", "GET /api/admin/b", "direct", "admin_only", "root", "PASS", "200", "false"),
		apiControl("c2", "GET /api/admin/b", "admin_reachable"),
	)
	expectAPI(t, b, map[string]facts.Conclusion{
		"api.anon_protected_access":      facts.ConclusionUnknown,
		"api.user_admin_access":          facts.ConclusionUnknown,
		"api.cross_owner_access":         facts.ConclusionNotApplicable,
		"api.invalidated_session_replay": facts.ConclusionNotApplicable,
	})
}

// 按端点覆盖 + 违规优先：B 端点未覆盖，但 A 端点有明确违规 → 仍 FAIL。
func TestAPIRulesPerEndpointGapWithFail(t *testing.T) {
	b := apiBundle(
		apiProbeAnon("f1", "GET /api/admin/a", "direct", "admin_only", "alice", "FAIL", "200", "false"),
		apiProbeAnon("f2", "GET /api/admin/b", "direct", "admin_only", "root", "PASS", "200", "false"),
		apiControl("c2", "GET /api/admin/b", "admin_reachable"),
	)
	expectAPI(t, b, map[string]facts.Conclusion{
		"api.anon_protected_access":      facts.ConclusionUnknown,
		"api.user_admin_access":          facts.ConclusionFail,
		"api.cross_owner_access":         facts.ConclusionNotApplicable,
		"api.invalidated_session_replay": facts.ConclusionNotApplicable,
	})
}

// 静态复核回归三轮：纯公开端点、重放全部合法跳过时重放规则判 NA
// （不适用，不是通过，也不是未确认）；非公开端点未运行仍为 UNKNOWN。
func TestAPIRulesReplayAllPublicSkipNA(t *testing.T) {
	allPublic := apiBundle(
		apiProbe("r1", "GET /api/open", "replay:logged_out", "public", "anon", "NOT_RUN", "0"),
		apiProbe("r2", "GET /api/status", "replay:logged_out", "public", "anon", "NOT_RUN", "0"),
	)
	got := apiConclusions(t, allPublic)
	if got["api.invalidated_session_replay"] != facts.ConclusionNotApplicable {
		t.Errorf("重放全部公开跳过：want NOT_APPLICABLE, got %s", got["api.invalidated_session_replay"])
	}
	mixed := apiBundle(
		apiProbe("r1", "GET /api/open", "replay:logged_out", "public", "anon", "NOT_RUN", "0"),
		apiProbe("r2", "GET /api/me", "replay:logged_out", "authenticated", "alice-logged-out", "NOT_RUN", "0"),
	)
	got = apiConclusions(t, mixed)
	if got["api.invalidated_session_replay"] != facts.ConclusionUnknown {
		t.Errorf("重放含非公开未运行：want UNKNOWN, got %s", got["api.invalidated_session_replay"])
	}
}
