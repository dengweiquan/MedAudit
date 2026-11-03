package rules

import (
	"strings"
	"testing"

	"medaudit/internal/facts"
)

// testBundleR 在 testBundle 基础上附加收据（证据门控测试用）。
func testBundleR(adapter facts.TargetType, fs []facts.Fact, rcs []facts.Receipt) *facts.FactBundle {
	b := testBundle(adapter, fs)
	b.Receipts = rcs
	return b
}

func receipt(templateID, status string) facts.Receipt {
	return facts.Receipt{TemplateID: templateID, TemplateVersion: "1", Status: status}
}

func resultsFor(t *testing.T, b *facts.FactBundle, baseline *Baseline, ruleID string) []TechnicalResult {
	t.Helper()
	var out []TechnicalResult
	for _, r := range DefaultRegistry().Evaluate(b, baseline) {
		if r.RuleID == ruleID {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		t.Fatalf("规则 %s 无评估结果", ruleID)
	}
	return out
}

func singleResult(t *testing.T, b *facts.FactBundle, baseline *Baseline, ruleID string) TechnicalResult {
	t.Helper()
	rs := resultsFor(t, b, baseline, ruleID)
	if len(rs) != 1 {
		t.Fatalf("规则 %s 期望 1 条结果，实际 %d 条", ruleID, len(rs))
	}
	return rs[0]
}

func expectConclusion(t *testing.T, r TechnicalResult, want facts.Conclusion) {
	t.Helper()
	if r.Conclusion != want {
		t.Errorf("规则 %s 期望结论 %s，实际 %s（detail=%s missing=%s）",
			r.RuleID, want, r.Conclusion, r.Detail, r.Missing)
	}
}

// 旧包：无 pg.settings 收据与事实（但有其他 account_config 事实，Requires 通过）→ 不得假 PASS。
func TestEvidenceOldBundle(t *testing.T) {
	b := testBundleR(facts.TargetDBPostgres, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "x", Status: facts.StatusObserved,
			Source: "pg.other", Attributes: map[string]string{"name": "x"}},
	}, nil)
	r := singleResult(t, b, &Baseline{}, "db.pg.ssl_off")
	expectConclusion(t, r, facts.ConclusionUnknown)
}

// 无关同类事实：有 pg.settings 收据与事实，但无 ssl 行 → UNKNOWN。
func TestEvidenceIrrelevantFacts(t *testing.T) {
	b := testBundleR(facts.TargetDBPostgres, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "server", Status: facts.StatusObserved,
			Source: "pg.settings", Attributes: map[string]string{"name": "listen_addresses", "setting": "localhost"}},
	}, []facts.Receipt{receipt("pg.settings", "ok")})
	r := singleResult(t, b, &Baseline{}, "db.pg.ssl_off")
	expectConclusion(t, r, facts.ConclusionUnknown)
}

// 字段缺失：ssl 事实无 name 属性 → 无法匹配 → UNKNOWN。
func TestEvidenceMissingFields(t *testing.T) {
	b := testBundleR(facts.TargetDBPostgres, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "server", Status: facts.StatusObserved,
			Source: "pg.settings", Attributes: map[string]string{}},
	}, []facts.Receipt{receipt("pg.settings", "ok")})
	r := singleResult(t, b, &Baseline{}, "db.pg.ssl_off")
	expectConclusion(t, r, facts.ConclusionUnknown)
}

// 读取失败：收据被拒绝 → UNKNOWN，且原因说明权限不足。
func TestEvidenceDenied(t *testing.T) {
	b := testBundleR(facts.TargetDBPostgres, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "server", Status: facts.StatusObserved,
			Source: "pg.other", Attributes: map[string]string{"name": "x"}},
	}, []facts.Receipt{receipt("pg.settings", "denied")})
	r := singleResult(t, b, &Baseline{}, "db.pg.ssl_off")
	expectConclusion(t, r, facts.ConclusionUnknown)
	if !strings.Contains(r.Missing, "权限不足") {
		t.Errorf("被拒绝原因应说明权限不足，实际 missing=%s", r.Missing)
	}
}

// 读取失败：收据失败 → UNKNOWN。
func TestEvidenceFailed(t *testing.T) {
	rc := receipt("pg.settings", "failed")
	rc.ErrorStage = "query"
	b := testBundleR(facts.TargetDBPostgres, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "server", Status: facts.StatusObserved,
			Source: "pg.other", Attributes: map[string]string{"name": "x"}},
	}, []facts.Receipt{rc})
	r := singleResult(t, b, &Baseline{}, "db.pg.ssl_off")
	expectConclusion(t, r, facts.ConclusionUnknown)
	if !strings.Contains(r.Missing, "采集失败") {
		t.Errorf("失败原因应说明采集失败，实际 missing=%s", r.Missing)
	}
}

// 零行：MSSQL 审计收据成功且零行 → “未配置任何审计” FAIL（不是未采集、不是 PASS）。
func TestEvidenceZeroRowAudit(t *testing.T) {
	b := testBundleR(facts.TargetDBSQLSrv, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "x", Status: facts.StatusObserved,
			Source: "mssql.server_config", Attributes: map[string]string{"name": "x"}},
	}, []facts.Receipt{receipt("mssql.server_audits", "ok")})
	r := singleResult(t, b, &Baseline{}, "db.mssql.audit_off")
	expectConclusion(t, r, facts.ConclusionFail)
	if !strings.Contains(r.Detail, "无任何审计配置") {
		t.Errorf("零行 FAIL 明细应说明无任何审计配置，实际 detail=%s", r.Detail)
	}
}

// 零行（严格型）：PG 收据成功但无 ssl 行 → UNKNOWN（不得判 PASS）。
func TestEvidenceZeroRowStrict(t *testing.T) {
	b := testBundleR(facts.TargetDBPostgres, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "server", Status: facts.StatusObserved,
			Source: "pg.settings", Attributes: map[string]string{"name": "listen_addresses", "setting": "localhost"}},
	}, []facts.Receipt{receipt("pg.settings", "ok")})
	r := singleResult(t, b, &Baseline{}, "db.pg.ssl_off")
	expectConclusion(t, r, facts.ConclusionUnknown)
}

// 截断：收据 partial 且无命中 → UNKNOWN；有命中 → FAIL 仍成立。
func TestEvidenceTruncated(t *testing.T) {
	rc := receipt("pg.settings", "partial")
	rc.Truncated = true
	off := testBundleR(facts.TargetDBPostgres, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "server", Status: facts.StatusObserved,
			Source: "pg.settings", Attributes: map[string]string{"name": "ssl", "setting": "on"}},
	}, []facts.Receipt{rc})
	r := singleResult(t, off, &Baseline{}, "db.pg.ssl_off")
	expectConclusion(t, r, facts.ConclusionUnknown)

	on := testBundleR(facts.TargetDBPostgres, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "server", Status: facts.StatusObserved,
			Source: "pg.settings", Attributes: map[string]string{"name": "ssl", "setting": "off"}},
	}, []facts.Receipt{rc})
	r = singleResult(t, on, &Baseline{}, "db.pg.ssl_off")
	expectConclusion(t, r, facts.ConclusionFail)
}

// 实例错配（代理）：事实无收据背书 → 不采信 → UNKNOWN（即使事实本身显示违规）。
func TestEvidenceNoReceiptBinding(t *testing.T) {
	b := testBundleR(facts.TargetDBPostgres, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "server", Status: facts.StatusObserved,
			Source: "pg.settings", Attributes: map[string]string{"name": "ssl", "setting": "off"}},
	}, nil)
	r := singleResult(t, b, &Baseline{}, "db.pg.ssl_off")
	expectConclusion(t, r, facts.ConclusionUnknown)
}

// sshd 不存在 → 两条 sshd 规则均为 NOT_APPLICABLE（不是 PASS）。
func TestEvidenceSSHNotApplicable(t *testing.T) {
	b := testBundleR(facts.TargetOSLinux, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "sshd_config", Status: facts.StatusUnsupported,
			Source: "linux.sshd", Attributes: map[string]string{"present": "false"}},
	}, []facts.Receipt{receipt("linux.sshd", "ok")})
	for _, id := range []string{"os.linux.ssh_password_auth", "os.linux.ssh_root_login"} {
		r := singleResult(t, b, &Baseline{}, id)
		expectConclusion(t, r, facts.ConclusionNotApplicable)
	}
}

// sshd 存在且口令/root 登录开启 → FAIL；无 sshd 事实 → UNKNOWN。
func TestEvidenceSSHPresentAndMissing(t *testing.T) {
	present := testBundleR(facts.TargetOSLinux, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "sshd_config", Status: facts.StatusObserved,
			Source: "linux.sshd", Attributes: map[string]string{
				"present": "true", "password_authentication": "yes", "permit_root_login": "yes"}},
	}, []facts.Receipt{receipt("linux.sshd", "ok")})
	r := singleResult(t, present, &Baseline{}, "os.linux.ssh_password_auth")
	expectConclusion(t, r, facts.ConclusionFail)
	r = singleResult(t, present, &Baseline{}, "os.linux.ssh_root_login")
	expectConclusion(t, r, facts.ConclusionFail)

	missing := testBundleR(facts.TargetOSLinux, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "x", Status: facts.StatusObserved,
			Source: "linux.other", Attributes: map[string]string{"name": "x"}},
	}, nil)
	r = singleResult(t, missing, &Baseline{}, "os.linux.ssh_password_auth")
	expectConclusion(t, r, facts.ConclusionUnknown)
}

// MSSQL 口令策略：旧包事实（无 is_policy_checked）→ UNKNOWN；OFF → FAIL；ON → PASS；无 SQL 登录 → PASS。
func TestEvidenceMSSQLPassword(t *testing.T) {
	oldBundle := testBundleR(facts.TargetDBSQLSrv, []facts.Fact{
		{FactID: "f1", Kind: facts.FactIdentity, Subject: "sa", Status: facts.StatusObserved,
			Source: "mssql.server_principals", Attributes: map[string]string{"principal_type": "SQL_LOGIN"}},
	}, []facts.Receipt{receipt("mssql.server_principals", "ok")})
	r := singleResult(t, oldBundle, &Baseline{}, "db.mssql.password_policy")
	expectConclusion(t, r, facts.ConclusionUnknown)

	off := testBundleR(facts.TargetDBSQLSrv, []facts.Fact{
		{FactID: "f1", Kind: facts.FactIdentity, Subject: "app", Status: facts.StatusObserved,
			Source: "mssql.server_principals", Attributes: map[string]string{
				"principal_type": "SQL_LOGIN", "is_disabled": "0", "is_policy_checked": "0", "is_expiration_checked": "1"}},
	}, []facts.Receipt{receipt("mssql.server_principals", "ok")})
	rs := resultsFor(t, off, &Baseline{}, "db.mssql.password_policy")
	foundFail := false
	for _, x := range rs {
		if x.Conclusion == facts.ConclusionFail {
			foundFail = true
		}
	}
	if !foundFail {
		t.Errorf("CHECK_POLICY=OFF 应判 FAIL，实际 %v", rs)
	}

	on := testBundleR(facts.TargetDBSQLSrv, []facts.Fact{
		{FactID: "f1", Kind: facts.FactIdentity, Subject: "app", Status: facts.StatusObserved,
			Source: "mssql.server_principals", Attributes: map[string]string{
				"principal_type": "SQL_LOGIN", "is_disabled": "0", "is_policy_checked": "1", "is_expiration_checked": "1"}},
	}, []facts.Receipt{receipt("mssql.server_principals", "ok")})
	r = singleResult(t, on, &Baseline{}, "db.mssql.password_policy")
	expectConclusion(t, r, facts.ConclusionPass)

	noLogin := testBundleR(facts.TargetDBSQLSrv, []facts.Fact{
		{FactID: "f1", Kind: facts.FactIdentity, Subject: "DOMAIN\\user", Status: facts.StatusObserved,
			Source: "mssql.server_principals", Attributes: map[string]string{
				"principal_type": "WINDOWS_LOGIN", "is_disabled": "0"}},
	}, []facts.Receipt{receipt("mssql.server_principals", "ok")})
	r = singleResult(t, noLogin, &Baseline{}, "db.mssql.password_policy")
	expectConclusion(t, r, facts.ConclusionPass)
}

// Oracle 审计：无 ora.parameters → UNKNOWN；NONE → FAIL；DB → PASS。
func TestEvidenceOracleAudit(t *testing.T) {
	none := testBundleR(facts.TargetDBOracle, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "x", Status: facts.StatusObserved,
			Source: "ora.profiles", Attributes: map[string]string{"profile": "DEFAULT"}},
	}, nil)
	r := singleResult(t, none, &Baseline{}, "db.oracle.audit_trail_off")
	expectConclusion(t, r, facts.ConclusionUnknown)

	off := testBundleR(facts.TargetDBOracle, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "server", Status: facts.StatusObserved,
			Source: "ora.parameters", Attributes: map[string]string{"name": "AUDIT_TRAIL", "value": "NONE"}},
	}, []facts.Receipt{receipt("ora.parameters", "ok")})
	r = singleResult(t, off, &Baseline{}, "db.oracle.audit_trail_off")
	expectConclusion(t, r, facts.ConclusionFail)

	on := testBundleR(facts.TargetDBOracle, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "server", Status: facts.StatusObserved,
			Source: "ora.parameters", Attributes: map[string]string{"name": "AUDIT_TRAIL", "value": "DB"}},
	}, []facts.Receipt{receipt("ora.parameters", "ok")})
	r = singleResult(t, on, &Baseline{}, "db.oracle.audit_trail_off")
	expectConclusion(t, r, facts.ConclusionPass)
}

// MySQL 口令策略：无 validate_password 事实 → UNKNOWN；LOW → FAIL；MEDIUM+长度 8 → PASS。
func TestEvidenceMySQLPassword(t *testing.T) {
	missing := testBundleR(facts.TargetDBMySQL, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "global", Status: facts.StatusObserved,
			Source: "mysql.server_config", Attributes: map[string]string{"name": "max_connections", "value": "100"}},
	}, []facts.Receipt{receipt("mysql.server_config", "ok")})
	r := singleResult(t, missing, &Baseline{}, "db.mysql.password_policy")
	expectConclusion(t, r, facts.ConclusionUnknown)

	low := testBundleR(facts.TargetDBMySQL, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "global", Status: facts.StatusObserved,
			Source: "mysql.server_config", Attributes: map[string]string{"name": "validate_password.policy", "value": "LOW"}},
	}, []facts.Receipt{receipt("mysql.server_config", "ok")})
	r = singleResult(t, low, &Baseline{}, "db.mysql.password_policy")
	expectConclusion(t, r, facts.ConclusionFail)

	ok := testBundleR(facts.TargetDBMySQL, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "global", Status: facts.StatusObserved,
			Source: "mysql.server_config", Attributes: map[string]string{"name": "validate_password.policy", "value": "MEDIUM"}},
		{FactID: "f2", Kind: facts.FactAccountConfig, Subject: "global", Status: facts.StatusObserved,
			Source: "mysql.server_config", Attributes: map[string]string{"name": "validate_password.length", "value": "8"}},
	}, []facts.Receipt{receipt("mysql.server_config", "ok")})
	r = singleResult(t, ok, &Baseline{}, "db.mysql.password_policy")
	expectConclusion(t, r, facts.ConclusionPass)
}

// PG 审计：三项均关 → FAIL；collector 开 → PASS；仅有无关设置 → UNKNOWN。
func TestEvidencePGAAudit(t *testing.T) {
	off := testBundleR(facts.TargetDBPostgres, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "server", Status: facts.StatusObserved,
			Source: "pg.settings", Attributes: map[string]string{"name": "logging_collector", "setting": "off"}},
		{FactID: "f2", Kind: facts.FactAccountConfig, Subject: "server", Status: facts.StatusObserved,
			Source: "pg.settings", Attributes: map[string]string{"name": "log_connections", "setting": "off"}},
		{FactID: "f3", Kind: facts.FactAccountConfig, Subject: "server", Status: facts.StatusObserved,
			Source: "pg.settings", Attributes: map[string]string{"name": "log_statement", "setting": "none"}},
	}, []facts.Receipt{receipt("pg.settings", "ok")})
	r := singleResult(t, off, &Baseline{}, "db.pg.audit_off")
	expectConclusion(t, r, facts.ConclusionFail)

	on := testBundleR(facts.TargetDBPostgres, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "server", Status: facts.StatusObserved,
			Source: "pg.settings", Attributes: map[string]string{"name": "logging_collector", "setting": "on"}},
	}, []facts.Receipt{receipt("pg.settings", "ok")})
	r = singleResult(t, on, &Baseline{}, "db.pg.audit_off")
	expectConclusion(t, r, facts.ConclusionPass)

	missing := testBundleR(facts.TargetDBPostgres, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "server", Status: facts.StatusObserved,
			Source: "pg.settings", Attributes: map[string]string{"name": "ssl", "setting": "on"}},
	}, []facts.Receipt{receipt("pg.settings", "ok")})
	r = singleResult(t, missing, &Baseline{}, "db.pg.audit_off")
	expectConclusion(t, r, facts.ConclusionUnknown)
}

// MSSQL 审计收据被拒绝 → UNKNOWN（区分于零行 FAIL）。
func TestEvidenceMSSQLAuditDenied(t *testing.T) {
	b := testBundleR(facts.TargetDBSQLSrv, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "x", Status: facts.StatusObserved,
			Source: "mssql.server_config", Attributes: map[string]string{"name": "x"}},
	}, []facts.Receipt{receipt("mssql.server_audits", "denied")})
	r := singleResult(t, b, &Baseline{}, "db.mssql.audit_off")
	expectConclusion(t, r, facts.ConclusionUnknown)
}

// 豁免：基线仍可屏蔽 FAIL，但不能把 UNKNOWN 洗成 PASS。
func TestEvidenceBaselineUntouched(t *testing.T) {
	allow := &Baseline{Allows: []BaselineAllow{
		{Subject: "server", Kind: "settings", Value: "ssl_off"},
	}}
	fail := testBundleR(facts.TargetDBPostgres, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "server", Status: facts.StatusObserved,
			Source: "pg.settings", Attributes: map[string]string{"name": "ssl", "setting": "off"}},
	}, []facts.Receipt{receipt("pg.settings", "ok")})
	r := singleResult(t, fail, allow, "db.pg.ssl_off")
	expectConclusion(t, r, facts.ConclusionPass)

	unknown := testBundleR(facts.TargetDBPostgres, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "server", Status: facts.StatusObserved,
			Source: "pg.settings", Attributes: map[string]string{"name": "listen_addresses", "setting": "localhost"}},
	}, []facts.Receipt{receipt("pg.settings", "ok")})
	r = singleResult(t, unknown, allow, "db.pg.ssl_off")
	expectConclusion(t, r, facts.ConclusionUnknown)
}

// 旧规则（未声明 Evidence）保持原有语义：无命中 → PASS。
func TestEvidenceOldRuleUnchanged(t *testing.T) {
	b := testBundleR(facts.TargetDBMySQL, []facts.Fact{
		{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "global", Status: facts.StatusObserved,
			Source: "mysql.server_config", Attributes: map[string]string{"name": "max_connections", "value": "100"}},
	}, nil)
	r := singleResult(t, b, &Baseline{}, "db.mysql.local_infile")
	expectConclusion(t, r, facts.ConclusionPass)
}
