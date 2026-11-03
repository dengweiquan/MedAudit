package platform

import (
	"encoding/json"
	"strings"
	"testing"

	"medaudit/internal/apiaudit"
)

func apiReportJSON(t *testing.T, rep apiaudit.Report) []byte {
	t.Helper()
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func apiComplianceCheck(endpoint, identity, probe, expectation string, status int, concl apiaudit.Conclusion) apiaudit.Check {
	return apiaudit.Check{Endpoint: endpoint, Identity: identity, Probe: probe,
		Expectation: apiaudit.AccessKind(expectation), Status: status, Conclusion: concl}
}

// 绑定 + 核实 + 全通过有对照 → 医疗-12 pass。
func TestAPIComplianceBoundPass(t *testing.T) {
	rep := apiaudit.Report{
		SchemaVersion: apiaudit.SchemaVersion, ReportID: "r1", Target: "http://api",
		HospitalID: "h1", AssetID: "a1",
		AnonymousIdentities: []string{"anon"},
		Summary:             map[string]int{"PASS": 999}, // 客户端谎报，须被重算纠正
		Checks: []apiaudit.Check{
			apiComplianceCheck("GET /api/profile", "anon", "direct", "authenticated", 403, apiaudit.ConclPass),
			apiComplianceCheck("GET /api/profile", "alice", "direct", "authenticated", 200, apiaudit.ConclPass),
			apiComplianceCheck("GET /api/admin/users", "root", "direct", "admin_only", 200, apiaudit.ConclPass),
			apiComplianceCheck("GET /api/admin/users", "alice", "direct", "admin_only", 403, apiaudit.ConclPass),
			apiComplianceCheck("GET /api/users/{id}", "alice", "self", "owner_or_admin", 200, apiaudit.ConclPass),
			apiComplianceCheck("GET /api/users/{id}", "bob", "cross-owner:alice", "owner_or_admin", 403, apiaudit.ConclPass),
			apiComplianceCheck("GET /api/me", "alice", "direct", "authenticated", 200, apiaudit.ConclPass),
			apiComplianceCheck("GET /api/me", "alice-logged-out", "replay:logged_out", "authenticated", 401, apiaudit.ConclPass),
		},
	}
	res, err := APICompliance(apiReportJSON(t, rep), true, true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Bound || res.Clause.Status != "pass" {
		t.Fatalf("want bound pass, got bound=%v status=%s note=%s", res.Bound, res.Clause.Status, res.Note)
	}
	if res.Summary["PASS"] != 8 || res.Summary["FAIL"] != 0 {
		t.Fatalf("summary must be recomputed from checks, got %+v", res.Summary)
	}
	for _, r := range res.Clause.Rules {
		if r.Outcome != outPass {
			t.Errorf("rule %s: want pass, got %s", r.RuleID, r.Outcome)
		}
	}
}

// 绑定 + 一条违规 → fail。
func TestAPIComplianceBoundFail(t *testing.T) {
	rep := apiaudit.Report{
		SchemaVersion: apiaudit.SchemaVersion, ReportID: "r2", Target: "http://api",
		HospitalID: "h1", AssetID: "a1", AnonymousIdentities: []string{"anon"},
		Checks: []apiaudit.Check{
			apiComplianceCheck("GET /api/admin/users", "alice", "direct", "admin_only", 200, apiaudit.ConclFail),
		},
	}
	res, err := APICompliance(apiReportJSON(t, rep), true, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Clause.Status != "fail" {
		t.Fatalf("want fail, got %s", res.Clause.Status)
	}
}

// 未绑定 → unknown，不纳入通过（即使检查全过）。
func TestAPIComplianceUnboundUnknown(t *testing.T) {
	rep := apiaudit.Report{
		SchemaVersion: apiaudit.SchemaVersion, ReportID: "r3", Target: "http://api",
		Checks: []apiaudit.Check{
			apiComplianceCheck("GET /api/profile", "alice", "direct", "authenticated", 200, apiaudit.ConclPass),
		},
	}
	res, err := APICompliance(apiReportJSON(t, rep), true, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Bound || res.Clause.Status != "unknown" || res.Note == "" {
		t.Fatalf("unbound must be unknown with note, got bound=%v status=%s note=%q", res.Bound, res.Clause.Status, res.Note)
	}
}

// 老格式（无 schema 版本）→ unknown。
func TestAPIComplianceOldFormatUnknown(t *testing.T) {
	rep := apiaudit.Report{
		ReportID: "r4", Target: "http://api", HospitalID: "h1", AssetID: "a1",
		Checks: []apiaudit.Check{
			apiComplianceCheck("GET /api/profile", "alice", "direct", "authenticated", 200, apiaudit.ConclPass),
		},
	}
	res, err := APICompliance(apiReportJSON(t, rep), true, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Clause.Status != "unknown" {
		t.Fatalf("old format must be unknown, got %s", res.Clause.Status)
	}
}

// 绑定但资产未经核实 → unknown。
func TestAPIComplianceUnverifiedUnknown(t *testing.T) {
	rep := apiaudit.Report{
		SchemaVersion: apiaudit.SchemaVersion, ReportID: "r5", Target: "http://api",
		HospitalID: "h1", AssetID: "a1",
		Checks: []apiaudit.Check{
			apiComplianceCheck("GET /api/profile", "alice", "direct", "authenticated", 200, apiaudit.ConclPass),
		},
	}
	res, err := APICompliance(apiReportJSON(t, rep), false, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Clause.Status != "unknown" {
		t.Fatalf("unverified binding must be unknown, got %s", res.Clause.Status)
	}
}

// 未认证上传的历史报告：即使绑定已核实也不作可信依据 → unknown。
func TestAPIComplianceUntrustedUnknown(t *testing.T) {
	rep := apiaudit.Report{
		SchemaVersion: apiaudit.SchemaVersion, ReportID: "r6", Target: "http://api",
		HospitalID: "h1", AssetID: "a1",
		Checks: []apiaudit.Check{
			apiComplianceCheck("GET /api/profile", "alice", "direct", "authenticated", 200, apiaudit.ConclPass),
		},
	}
	res, err := APICompliance(apiReportJSON(t, rep), true, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Clause.Status != "unknown" {
		t.Fatalf("untrusted upload must be unknown, got %s", res.Clause.Status)
	}
	if !strings.Contains(res.Note, "未认证") {
		t.Fatalf("untrusted note must mention 未认证，got %q", res.Note)
	}
}

// 统计重算：客户端 Summary 全错时以 checks 为准。
func TestCountAPIAuditSummary(t *testing.T) {
	got := CountAPIAuditSummary([]apiaudit.Check{
		{Conclusion: apiaudit.ConclPass}, {Conclusion: apiaudit.ConclFail},
		{Conclusion: apiaudit.ConclUnknown}, {Conclusion: apiaudit.ConclNotRun},
		{Conclusion: apiaudit.ConclPass},
	})
	if got["PASS"] != 2 || got["FAIL"] != 1 || got["UNKNOWN"] != 1 || got["NOT_RUN"] != 1 {
		t.Fatalf("wrong recompute: %+v", got)
	}
}
