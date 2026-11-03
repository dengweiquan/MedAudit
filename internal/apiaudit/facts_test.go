package apiaudit

import (
	"strings"
	"testing"

	"medaudit/internal/facts"
)

func apiCheck(endpoint, identity, probe, expectation string, status int, concl Conclusion, detail string) Check {
	return Check{Endpoint: endpoint, Identity: identity, Probe: probe,
		Expectation: AccessKind(expectation), Status: status, Conclusion: concl, Detail: detail}
}

func findFacts(fs []facts.Fact, source, endpoint string) []facts.Fact {
	var out []facts.Fact
	for _, f := range fs {
		if f.Source == source && f.Subject == endpoint {
			out = append(out, f)
		}
	}
	return out
}

func hasControl(fs []facts.Fact, endpoint, control string) bool {
	for _, f := range findFacts(fs, "api.control", endpoint) {
		if f.Attributes["control"] == control {
			return true
		}
	}
	return false
}

// 转换覆盖四类探针、正向对照派生、匿名分流与脱敏。
func TestToFactsCoverage(t *testing.T) {
	rep := &Report{
		SchemaVersion:       SchemaVersion,
		ReportID:            "apiaudit-test",
		Target:              "http://127.0.0.1:19090",
		AnonymousIdentities: []string{"anon"},
		Checks: []Check{
			apiCheck("GET /api/public/health", "anon", "direct", "public", 200, ConclPass, "公开端点匿名可达"),
			apiCheck("GET /api/profile", "anon", "direct", "authenticated", 200, ConclFail, "匿名身份可达需认证端点"),
			apiCheck("GET /api/profile", "alice", "direct", "authenticated", 200, ConclPass, "已认证身份可达"),
			apiCheck("GET /api/admin/users", "root", "direct", "admin_only", 200, ConclPass, "管理员可达"),
			apiCheck("GET /api/admin/users", "alice", "direct", "admin_only", 403, ConclPass, "非管理员被拒"),
			apiCheck("GET /api/admin/users", "anon", "direct", "admin_only", 200, ConclFail, "非管理员身份可达管理员端点（垂直越权）"),
			apiCheck("GET /api/users/{user_id}", "alice", "self", "owner_or_admin", 200, ConclPass, "属主可读自有资源"),
			apiCheck("GET /api/users/{user_id}", "bob", "cross-owner:alice", "owner_or_admin", 200, ConclFail, "跨主体读到 alice 的私有数据（canary 命中，水平越权）"),
			apiCheck("GET /api/users/{user_id}", "bob", "cross-owner:alice", "owner_or_admin", 200, ConclUnknown, "跨主体返回 2xx 但未命中 canary；可能为脱敏/共享数据，证据不足"),
			apiCheck("GET /api/users/{user_id}", "bob", "cross-owner:alice", "owner_or_admin", 403, ConclPass, "跨主体被拒"),
			apiCheck("GET /api/me", "alice-logged-out", "replay:logged_out", "authenticated", 200, ConclFail, "失效会话（logged_out）仍被接受"),
			apiCheck("GET /api/me", "alice-logged-out", "replay:logged_out", "authenticated", 401, ConclPass, "失效会话（logged_out）被拒"),
			apiCheck("POST /api/notes", "-", "readonly-policy", "authenticated", 0, ConclNotRun, "写方法在默认只读策略下跳过"),
			apiCheck("GET /api/secret", "alice", "direct", "authenticated", 500, ConclUnknown, "传输错误：password=Hunter2! 泄露"),
		},
	}
	fs := ToFacts(rep)
	if len(fs) == 0 {
		t.Fatal("no facts produced")
	}
	// 匿名分流：管理员端点匿名 FAIL 带 anonymous=true，已认证 FAIL 带 false。
	adminFacts := findFacts(fs, "api.audit", "GET /api/admin/users")
	var anonTrue, aliceFalse bool
	for _, f := range adminFacts {
		if f.Attributes["identity"] == "anon" && f.Attributes["outcome"] == "FAIL" && f.Attributes["anonymous"] == "true" {
			anonTrue = true
		}
		if f.Attributes["identity"] == "alice" && f.Attributes["anonymous"] == "false" {
			aliceFalse = true
		}
	}
	if !anonTrue || !aliceFalse {
		t.Fatalf("anonymous split wrong: anonTrue=%v aliceFalse=%v", anonTrue, aliceFalse)
	}
	// 正向对照派生：公开/已认证/管理员/属主/端点五类。
	if !hasControl(fs, "GET /api/public/health", "public_reachable") {
		t.Error("missing public_reachable")
	}
	if !hasControl(fs, "GET /api/profile", "authed_reachable") {
		t.Error("missing authed_reachable")
	}
	if !hasControl(fs, "GET /api/admin/users", "admin_reachable") {
		t.Error("missing admin_reachable")
	}
	if !hasControl(fs, "GET /api/users/{user_id}", "self_reachable") {
		t.Error("missing self_reachable")
	}
	// /api/me 在本报告中只有重放探针（FAIL 2xx + PASS 拒答），无差分 2xx，
	// 故不应派生 endpoint_reachable（重放探针本身不是正向对照）。
	if hasControl(fs, "GET /api/me", "endpoint_reachable") {
		t.Error("endpoint_reachable must NOT be derived from replay probes alone")
	}
	// 脱敏：失败原因原文不得含秘密。
	for _, f := range fs {
		if strings.Contains(f.Attributes["detail"], "Hunter2") {
			t.Fatalf("secret leaked into fact detail: %q", f.Attributes["detail"])
		}
	}
	// NOT_RUN 事实保留（不丢弃，不当作通过）。
	nr := findFacts(fs, "api.audit", "POST /api/notes")
	if len(nr) != 1 || nr[0].Attributes["outcome"] != "NOT_RUN" {
		t.Fatalf("NOT_RUN fact missing: %+v", nr)
	}
}

// 老报告无匿名身份清单时，管理员端点事实不带 anonymous 属性（规则端分流为垂直）。
func TestToFactsOldReportNoAnonAttr(t *testing.T) {
	rep := &Report{ReportID: "old", Target: "http://x",
		Checks: []Check{
			apiCheck("GET /api/admin/users", "someone", "direct", "admin_only", 200, ConclFail, "非管理员身份可达管理员端点"),
		},
	}
	fs := ToFacts(rep)
	if len(fs) != 1 {
		t.Fatalf("want 1 fact, got %d", len(fs))
	}
	if _, ok := fs[0].Attributes["anonymous"]; ok {
		t.Fatalf("old report must not carry anonymous attr, got %q", fs[0].Attributes["anonymous"])
	}
}
