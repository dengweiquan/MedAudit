package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"medaudit/internal/apiaudit"
	"medaudit/internal/platform"
)

// 静态复核回归：API 审计报告上传信任边界——未登录不得上传；
// 认证上传记可信；未认证历史报告只保留、不作可信合规依据。
func TestAPIAuditUploadTrust(t *testing.T) {
	s := newTestServer(t, nil)
	rep := apiaudit.Report{
		SchemaVersion: apiaudit.SchemaVersion, ReportID: "up-1", Target: "http://api",
		HospitalID: "h1", AssetID: "a1",
		AnonymousIdentities: []string{"anon"},
		Checks: []apiaudit.Check{
			{Endpoint: "GET /api/profile", Identity: "anon", Probe: "direct",
				Expectation: apiaudit.AccessAuthenticated, Status: 403, Conclusion: apiaudit.ConclPass},
			{Endpoint: "GET /api/profile", Identity: "alice", Probe: "direct",
				Expectation: apiaudit.AccessAuthenticated, Status: 200, Conclusion: apiaudit.ConclPass},
		},
	}
	if err := platform.CreateHospital(s.db, "h1", "医院一"); err != nil {
		t.Fatal(err)
	}
	if err := platform.CreateAsset(s.db, platform.Asset{ID: "a1", HospitalID: "h1", Kind: "api", Name: "API"}); err != nil {
		t.Fatal(err)
	}

	// 未登录上传 → 401。
	status, _, _ := s.do(t, http.MethodPost, "/api/v1/api-audits", rep, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("未登录上传应 401，实际 %d", status)
	}
	// 登录后上传 → 201 且记可信。
	cookie := s.login(t, platform.DefaultAdminUser, platform.DefaultAdminPassword)
	status, _, _ = s.do(t, http.MethodPost, "/api/v1/api-audits", rep, []*http.Cookie{cookie})
	if status != http.StatusCreated {
		t.Fatalf("登录后上传应 201，实际 %d", status)
	}
	var trusted int
	if err := s.db.QueryRow(`SELECT upload_authenticated FROM api_audit_reports WHERE report_id = 'up-1'`).Scan(&trusted); err != nil || trusted != 1 {
		t.Fatalf("认证上传应记 trusted=1，得到 %d（err=%v）", trusted, err)
	}
	// 合规判定：认证上传 + 绑定一致 → 正常评估（匿名拒答 + 已认证对照 = 通过）。
	status, data, _ := s.do(t, http.MethodGet, "/api/v1/api-audits/up-1/compliance", nil, []*http.Cookie{cookie})
	if status != http.StatusOK {
		t.Fatalf("合规判定应 200，实际 %d：%s", status, data)
	}
	var res platform.APIComplianceResult
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatal(err)
	}
	if res.Clause.Status != "pass" {
		t.Fatalf("认证上传的合规判定应为 pass，得到 status=%s note=%q", res.Clause.Status, res.Note)
	}
	// 未认证历史报告（直接插库，trusted=0）：合规判定 → unknown + 未认证注记。
	legacy := rep
	legacy.ReportID = "up-legacy"
	legacyRaw, _ := json.Marshal(legacy)
	if _, err := s.db.Exec(
		`INSERT INTO api_audit_reports (report_id, target, execution, hospital_id, asset_id, total, pass_count, fail_count, unknown_count, not_run_count, upload_authenticated, report)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		legacy.ReportID, legacy.Target, legacy.Execution, legacy.HospitalID, legacy.AssetID,
		len(legacy.Checks), 1, 0, 0, 0, string(legacyRaw)); err != nil {
		t.Fatal(err)
	}
	status, data, _ = s.do(t, http.MethodGet, "/api/v1/api-audits/up-legacy/compliance", nil, []*http.Cookie{cookie})
	if status != http.StatusOK {
		t.Fatalf("历史报告合规判定应 200，实际 %d：%s", status, data)
	}
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatal(err)
	}
	if res.Clause.Status != "unknown" || !strings.Contains(res.Note, "未认证") {
		t.Fatalf("未认证历史报告合规应为 unknown + 未认证注记，得到 status=%s note=%q", res.Clause.Status, res.Note)
	}
}

// 静态复核回归二轮：同 report_id 的认证重传只返回 duplicate，不升级信任；
// 合规注记须明确要求重新运行生成新 ID。
func TestAPIAuditUploadDuplicateNoTrustUpgrade(t *testing.T) {
	s := newTestServer(t, nil)
	rep := apiaudit.Report{
		SchemaVersion: apiaudit.SchemaVersion, ReportID: "dup-1", Target: "http://api",
		HospitalID: "h1", AssetID: "a1",
		Checks: []apiaudit.Check{
			{Endpoint: "GET /api/profile", Identity: "anon", Probe: "direct",
				Expectation: apiaudit.AccessAuthenticated, Status: 403, Conclusion: apiaudit.ConclPass},
		},
	}
	if err := platform.CreateHospital(s.db, "h1", "医院一"); err != nil {
		t.Fatal(err)
	}
	if err := platform.CreateAsset(s.db, platform.Asset{ID: "a1", HospitalID: "h1", Kind: "api", Name: "API"}); err != nil {
		t.Fatal(err)
	}
	// 先以未认证行插库（历史报告，trusted=0）。
	raw, _ := json.Marshal(rep)
	if _, err := s.db.Exec(
		`INSERT INTO api_audit_reports (report_id, target, execution, hospital_id, asset_id, total, pass_count, fail_count, unknown_count, not_run_count, upload_authenticated, report)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		rep.ReportID, rep.Target, rep.Execution, rep.HospitalID, rep.AssetID,
		len(rep.Checks), 1, 0, 0, 0, string(raw)); err != nil {
		t.Fatal(err)
	}
	// 登录后以同 ID 重传 → duplicate，信任不升级。
	cookie := s.login(t, platform.DefaultAdminUser, platform.DefaultAdminPassword)
	status, data, _ := s.do(t, http.MethodPost, "/api/v1/api-audits", rep, []*http.Cookie{cookie})
	if status != http.StatusOK {
		t.Fatalf("同 ID 重传应 200 duplicate，实际 %d：%s", status, data)
	}
	var dup map[string]any
	if err := json.Unmarshal(data, &dup); err != nil || dup["status"] != "duplicate" {
		t.Fatalf("同 ID 重传应返回 duplicate，得到 %s", data)
	}
	var trusted int
	if err := s.db.QueryRow(`SELECT upload_authenticated FROM api_audit_reports WHERE report_id = 'dup-1'`).Scan(&trusted); err != nil || trusted != 0 {
		t.Fatalf("同 ID 重传后信任仍须为 0，得到 %d（err=%v）", trusted, err)
	}
	// 合规注记须明确要求重新运行生成新 ID，而非仅“重新上传”。
	status, data, _ = s.do(t, http.MethodGet, "/api/v1/api-audits/dup-1/compliance", nil, []*http.Cookie{cookie})
	if status != http.StatusOK {
		t.Fatalf("合规判定应 200，实际 %d：%s", status, data)
	}
	var res platform.APIComplianceResult
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatal(err)
	}
	if res.Clause.Status != "unknown" || !strings.Contains(res.Note, "新 report_id") {
		t.Fatalf("未认证历史报告合规应为 unknown + 要求新 report_id 的注记，得到 status=%s note=%q", res.Clause.Status, res.Note)
	}
}
