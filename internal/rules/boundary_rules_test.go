package rules

import (
	"strings"
	"testing"

	"medaudit/internal/facts"
)

// ---- MSSQL 审计零行可见性 ----

func mssqlAuditBundle(auditFacts []facts.Fact, auditStatus string, vis string) *facts.FactBundle {
	fs := append([]facts.Fact{}, auditFacts...)
	var rcs []facts.Receipt
	rcs = append(rcs, facts.Receipt{TemplateID: "mssql.server_audits", TemplateVersion: "1", Status: auditStatus})
	if vis != "" {
		fs = append(fs, facts.Fact{FactID: "f-vis", Kind: facts.FactAccountConfig, Subject: "audit-visibility",
			Status: facts.StatusObserved, Source: "mssql.audit_visibility",
			Attributes: map[string]string{"visibility": vis}})
		rcs = append(rcs, facts.Receipt{TemplateID: "mssql.audit_visibility", TemplateVersion: "1", Status: "ok"})
	}
	return testBundleR(facts.TargetDBSQLSrv, fs, rcs)
}

func mssqlAuditFact(name, enabled string) facts.Fact {
	return facts.Fact{FactID: "f-" + name, Kind: facts.FactAccountConfig, Subject: name,
		Status: facts.StatusObserved, Source: "mssql.server_audits",
		Attributes: map[string]string{"is_state_enabled": enabled}}
}

func TestMSSQLAuditZeroRowsVisibility(t *testing.T) {
	// 零行 + 可见性充分 → FAIL（认定未配置）。
	b := mssqlAuditBundle(nil, "ok", "sufficient")
	r := singleResult(t, b, &Baseline{}, "db.mssql.audit_off")
	expectConclusion(t, r, facts.ConclusionFail)

	// 零行 + 可见性不足 → UNKNOWN（不自动提权）。
	b = mssqlAuditBundle(nil, "ok", "uncertain")
	r = singleResult(t, b, &Baseline{}, "db.mssql.audit_off")
	expectConclusion(t, r, facts.ConclusionUnknown)

	// 零行 + 旧包无自查事实 → UNKNOWN。
	b = mssqlAuditBundle(nil, "ok", "")
	r = singleResult(t, b, &Baseline{}, "db.mssql.audit_off")
	expectConclusion(t, r, facts.ConclusionUnknown)

	// 零行 + 未采集（无收据）→ UNKNOWN（零行与未采集必须区分）。
	b = testBundleR(facts.TargetDBSQLSrv, nil, nil)
	r = singleResult(t, b, &Baseline{}, "db.mssql.audit_off")
	expectConclusion(t, r, facts.ConclusionUnknown)

	// 截断 + 已见启用审计 → PASS（已观察到的启用事实可靠）。
	b = mssqlAuditBundle([]facts.Fact{mssqlAuditFact("audit1", "1")}, "partial", "")
	r = singleResult(t, b, &Baseline{}, "db.mssql.audit_off")
	expectConclusion(t, r, facts.ConclusionPass)

	// 截断 + 零行 → UNKNOWN（缺席判断不能在截断结果上推断）。
	b = mssqlAuditBundle(nil, "partial", "sufficient")
	r = singleResult(t, b, &Baseline{}, "db.mssql.audit_off")
	expectConclusion(t, r, facts.ConclusionUnknown)

	// 截断 + 仅见未启用审计 → UNKNOWN（被截断部分可能含启用审计）。
	b = mssqlAuditBundle([]facts.Fact{mssqlAuditFact("audit1", "0")}, "partial", "")
	r = singleResult(t, b, &Baseline{}, "db.mssql.audit_off")
	expectConclusion(t, r, facts.ConclusionUnknown)

	// 完整 + 仅见未启用审计 → FAIL（完整清单，判断可靠）。
	b = mssqlAuditBundle([]facts.Fact{mssqlAuditFact("audit1", "0")}, "ok", "")
	r = singleResult(t, b, &Baseline{}, "db.mssql.audit_off")
	expectConclusion(t, r, facts.ConclusionFail)
}

// ---- 收据绑定：错实例/旧运行/冲突收据 ----

func TestReceiptBinding(t *testing.T) {
	// 他项收据（mssql.server_config 成功）不能为审计规则背书 → UNKNOWN。
	b := testBundleR(facts.TargetDBSQLSrv,
		[]facts.Fact{mssqlAuditFact("audit1", "1")},
		[]facts.Receipt{{TemplateID: "mssql.server_config", TemplateVersion: "1", Status: "ok"}})
	r := singleResult(t, b, &Baseline{}, "db.mssql.audit_off")
	expectConclusion(t, r, facts.ConclusionUnknown)

	// 冲突收据（ok 与 denied 并存）→ UNKNOWN，不取最乐观者。
	b = testBundleR(facts.TargetDBSQLSrv,
		[]facts.Fact{mssqlAuditFact("audit1", "1")},
		[]facts.Receipt{
			{TemplateID: "mssql.server_audits", TemplateVersion: "1", Status: "ok"},
			{TemplateID: "mssql.server_audits", TemplateVersion: "1", Status: "denied"},
		})
	r = singleResult(t, b, &Baseline{}, "db.mssql.audit_off")
	expectConclusion(t, r, facts.ConclusionUnknown)

	// 部分成功后失败（partial + failed）→ UNKNOWN。
	b = testBundleR(facts.TargetDBSQLSrv,
		[]facts.Fact{mssqlAuditFact("audit1", "1")},
		[]facts.Receipt{
			{TemplateID: "mssql.server_audits", TemplateVersion: "1", Status: "partial"},
			{TemplateID: "mssql.server_audits", TemplateVersion: "1", Status: "failed"},
		})
	r = singleResult(t, b, &Baseline{}, "db.mssql.audit_off")
	expectConclusion(t, r, facts.ConclusionUnknown)
}

// ---- 无证据不得判 NA ----

func TestNoEvidenceNotNA(t *testing.T) {
	// RDP 规则：无事实无收据 → UNKNOWN，不是 NA。
	b := testBundleR(facts.TargetOSWindows, nil, nil)
	r := singleResult(t, b, &Baseline{}, "os.windows.rdp_nla_disabled")
	expectConclusion(t, r, facts.ConclusionUnknown)

	// Oracle sqlnet 规则：无事实无收据 → UNKNOWN，不是 NA。
	b = testBundleR(facts.TargetOSLinux, nil, nil)
	r = singleResult(t, b, &Baseline{}, "os.linux.oracle_native_encryption_not_required")
	expectConclusion(t, r, facts.ConclusionUnknown)
}

// ---- partial 对独立违规仍可 FAIL，对无命中则 UNKNOWN ----

func TestPartialPresenceRule(t *testing.T) {
	mysqlFact := func(name, value string) facts.Fact {
		return facts.Fact{FactID: "f-" + name, Kind: facts.FactAccountConfig, Subject: "global",
			Status: facts.StatusObserved, Source: "mysql.server_config",
			Attributes: map[string]string{"name": name, "value": value}}
	}
	// 截断 + 已见 LOW 策略 → FAIL（独立违规已观察到）。
	b := testBundleR(facts.TargetDBMySQL, []facts.Fact{mysqlFact("validate_password.policy", "LOW")},
		[]facts.Receipt{{TemplateID: "mysql.server_config", TemplateVersion: "1", Status: "partial"}})
	r := singleResult(t, b, &Baseline{}, "db.mysql.password_policy")
	expectConclusion(t, r, facts.ConclusionFail)

	// 截断 + 未见违规（MEDIUM）→ UNKNOWN（不能由无命中推断通过）。
	b = testBundleR(facts.TargetDBMySQL, []facts.Fact{mysqlFact("validate_password.policy", "MEDIUM")},
		[]facts.Receipt{{TemplateID: "mysql.server_config", TemplateVersion: "1", Status: "partial"}})
	r = singleResult(t, b, &Baseline{}, "db.mysql.password_policy")
	expectConclusion(t, r, facts.ConclusionUnknown)
}

// ---- SSH root 口令登录须合取口令鉴别 ----

func TestSSHRootLoginConjunction(t *testing.T) {
	sshd := func(permit, pa string) *facts.FactBundle {
		attrs := map[string]string{"present": "true", "file": "/etc/ssh/sshd_config", "permit_root_login": permit}
		if pa != "" {
			attrs["password_authentication"] = pa
		}
		return testBundleR(facts.TargetOSLinux, []facts.Fact{{
			FactID: "f-sshd", Kind: facts.FactAccountConfig, Subject: "sshd_config",
			Status: facts.StatusObserved, Source: "linux.sshd", Attributes: attrs,
		}}, []facts.Receipt{{TemplateID: "linux.sshd", TemplateVersion: "1", Status: "ok"}})
	}
	// PermitRootLogin=yes + 口令鉴别开启 → FAIL。
	r := singleResult(t, sshd("yes", "yes"), &Baseline{}, "os.linux.ssh_root_login")
	expectConclusion(t, r, facts.ConclusionFail)

	// PermitRootLogin=yes + 口令鉴别缺省（即 yes）→ FAIL。
	r = singleResult(t, sshd("yes", ""), &Baseline{}, "os.linux.ssh_root_login")
	expectConclusion(t, r, facts.ConclusionFail)

	// PermitRootLogin=yes 但 PasswordAuthentication=no（root 只能密钥登录）→ 不判口令登录。
	r = singleResult(t, sshd("yes", "no"), &Baseline{}, "os.linux.ssh_root_login")
	expectConclusion(t, r, facts.ConclusionPass)

	// PermitRootLogin=prohibit-password → 不判口令登录。
	r = singleResult(t, sshd("prohibit-password", "yes"), &Baseline{}, "os.linux.ssh_root_login")
	expectConclusion(t, r, facts.ConclusionPass)
}

// ---- PG 审计：收集器不等于审计事件 ----

func pgSettingsBundle(vals map[string]string, status string) *facts.FactBundle {
	var fs []facts.Fact
	for k, v := range vals {
		fs = append(fs, facts.Fact{FactID: "f-" + k, Kind: facts.FactAccountConfig, Subject: "server",
			Status: facts.StatusObserved, Source: "pg.settings",
			Attributes: map[string]string{"name": k, "setting": v}})
	}
	return testBundleR(facts.TargetDBPostgres, fs,
		[]facts.Receipt{{TemplateID: "pg.settings", TemplateVersion: "1", Status: status}})
}

func TestPGAuditCollectorNotEvent(t *testing.T) {
	// logging_collector=on 但事件开关全关 → FAIL（收集器不等于审计事件）。
	b := pgSettingsBundle(map[string]string{
		"logging_collector": "on", "log_connections": "off", "log_statement": "none"}, "ok")
	r := singleResult(t, b, &Baseline{}, "db.pg.audit_off")
	expectConclusion(t, r, facts.ConclusionFail)

	// 收集器 off 但 log_connections=on（事件走 stderr/syslog）→ PASS（不把其他输出路径当未审计）。
	b = pgSettingsBundle(map[string]string{
		"logging_collector": "off", "log_connections": "on", "log_statement": "none"}, "ok")
	r = singleResult(t, b, &Baseline{}, "db.pg.audit_off")
	expectConclusion(t, r, facts.ConclusionPass)

	// 截断 + 仅见 log_connections=off → UNKNOWN（缺席判断不能在截断结果上推断）。
	b = pgSettingsBundle(map[string]string{"log_connections": "off"}, "partial")
	r = singleResult(t, b, &Baseline{}, "db.pg.audit_off")
	expectConclusion(t, r, facts.ConclusionUnknown)

	// 截断 + 已见 log_statement=ddl → PASS（事件开关已观察到）。
	b = pgSettingsBundle(map[string]string{"log_statement": "ddl"}, "partial")
	r = singleResult(t, b, &Baseline{}, "db.pg.audit_off")
	expectConclusion(t, r, facts.ConclusionPass)
}

// ---- Oracle 审计收窄为传统审计 ----

func TestOracleAuditNarrowed(t *testing.T) {
	var spec *RuleSpec
	for i := range serverConfigRules {
		if serverConfigRules[i].spec.ID == "db.oracle.audit_trail_off" {
			spec = &serverConfigRules[i].spec
			break
		}
	}
	if spec == nil {
		t.Fatal("rule not found")
	}
	if spec.Name != "Oracle 传统审计未启用" {
		t.Fatalf("want narrowed name, got %q", spec.Name)
	}
	if !strings.Contains(spec.Description, "统一审计") {
		t.Fatalf("description must scope out unified auditing: %q", spec.Description)
	}
	// NONE 仍判 FAIL（收窄不断言无审计，只收窄结论口径）。
	b := testBundleR(facts.TargetDBOracle, []facts.Fact{{
		FactID: "f-a", Kind: facts.FactAccountConfig, Subject: "server",
		Status: facts.StatusObserved, Source: "ora.parameters",
		Attributes: map[string]string{"name": "AUDIT_TRAIL", "value": "NONE"},
	}}, []facts.Receipt{{TemplateID: "ora.parameters", TemplateVersion: "1", Status: "ok"}})
	r := singleResult(t, b, &Baseline{}, "db.oracle.audit_trail_off")
	expectConclusion(t, r, facts.ConclusionFail)
}
