package rules

import (
	"testing"

	"medaudit/internal/facts"
)

func testBundle(adapter facts.TargetType, fs []facts.Fact) *facts.FactBundle {
	return &facts.FactBundle{
		SchemaVersion: facts.SchemaVersion,
		BundleID:      "b-test", PlanID: "p-test",
		Collector: facts.CollectorInfo{Adapter: adapter},
		Scope:     facts.Scope{HospitalID: "h", AssetID: "a", TargetType: adapter},
		Identities: facts.Identities{
			CollectorIdentity: "c@collector", TargetIdentity: "t@target",
		},
		Facts: fs,
	}
}

func TestMySQLGlobalAdmin(t *testing.T) {
	b := testBundle(facts.TargetDBMySQL, []facts.Fact{
		{FactID: "f1", Kind: facts.FactPrivilege, Subject: "app@%", Status: facts.StatusObserved,
			Attributes: map[string]string{"privilege": "SUPER"}, Scope: "*.*"},
		{FactID: "f2", Kind: facts.FactPrivilege, Subject: "ro@%", Status: facts.StatusObserved,
			Attributes: map[string]string{"privilege": "SELECT"}, Scope: "his.*"},
	})
	results := DefaultRegistry().Evaluate(b, &Baseline{})
	var fails []TechnicalResult
	for _, r := range results {
		if r.RuleID == "db.mysql.global_admin" && r.Conclusion == facts.ConclusionFail {
			fails = append(fails, r)
		}
	}
	if len(fails) != 1 || fails[0].Subject != "app@%" {
		t.Fatalf("global_admin fails = %+v", fails)
	}
	// 基线允许后不再 FAIL
	base := &Baseline{Allows: []BaselineAllow{
		{Subject: "app@%", Kind: "privilege", Value: "SUPER", Scope: "*.*", Reason: "备份"},
	}}
	results = DefaultRegistry().Evaluate(b, base)
	for _, r := range results {
		if r.RuleID == "db.mysql.global_admin" && r.Conclusion == facts.ConclusionFail {
			t.Fatal("基线允许后仍 FAIL")
		}
	}
}

func TestUnknownWhenMissingFacts(t *testing.T) {
	b := testBundle(facts.TargetDBMySQL, nil) // 无 privilege 事实
	results := DefaultRegistry().Evaluate(b, &Baseline{})
	for _, r := range results {
		if r.RuleID == "db.mysql.global_admin" && r.Conclusion != facts.ConclusionUnknown {
			t.Fatalf("缺失前置事实时期望 UNKNOWN，得到 %s", r.Conclusion)
		}
	}
}

func TestNotApplicable(t *testing.T) {
	b := testBundle(facts.TargetDBMySQL, []facts.Fact{
		{FactID: "f1", Kind: facts.FactPrivilege, Subject: "x", Status: facts.StatusObserved},
	})
	results := DefaultRegistry().Evaluate(b, &Baseline{})
	for _, r := range results {
		if r.RuleID == "db.mssql.sysadmin" && r.Conclusion != facts.ConclusionNotApplicable {
			t.Fatalf("跨目标期望 NOT_APPLICABLE，得到 %s", r.Conclusion)
		}
	}
}

func TestLinuxWritableFile(t *testing.T) {
	b := testBundle(facts.TargetOSLinux, []facts.Fact{
		{FactID: "f-d0", Kind: facts.FactFilePerm, Subject: "/usr/sbin/cron",
			Status:     facts.StatusObserved,
			Attributes: map[string]string{"mode": "0777", "writable_by_other": "true"}},
	})
	results := DefaultRegistry().Evaluate(b, &Baseline{})
	found := false
	for _, r := range results {
		if r.RuleID == "os.linux.writable_service_file" && r.Conclusion == facts.ConclusionFail {
			found = true
		}
	}
	if !found {
		t.Fatal("可写的服务文件未被检出")
	}
}

func TestOracleDBARole(t *testing.T) {
	b := testBundle(facts.TargetDBOracle, []facts.Fact{
		{FactID: "f1", Kind: facts.FactRoleEdge, Subject: "APP_USER",
			Status: facts.StatusObserved, PermissionPath: []string{"DBA", "APP_USER"},
			Activation: facts.ActivationDefault},
	})
	results := DefaultRegistry().Evaluate(b, &Baseline{})
	found := false
	for _, r := range results {
		if r.RuleID == "db.oracle.dba_role" && r.Conclusion == facts.ConclusionFail {
			found = true
			if len(r.Evidence) == 0 {
				t.Error("FAIL 缺少证据引用")
			}
		}
	}
	if !found {
		t.Fatal("DBA 角色未被检出")
	}
}

func TestLinuxHighCapabilitiesDetail(t *testing.T) {
	proc := func(attrs map[string]string) facts.Fact {
		return facts.Fact{FactID: "f-p1", Kind: facts.FactProcess, Subject: "kf7/bootid/609/1795",
			Status: facts.StatusObserved, Attributes: attrs}
	}
	hit := func(fs []facts.Fact) (bool, string) {
		for _, r := range DefaultRegistry().Evaluate(testBundle(facts.TargetOSLinux, fs), &Baseline{}) {
			if r.RuleID == "os.linux.high_capabilities" && r.Conclusion == facts.ConclusionFail {
				return true, r.Detail
			}
		}
		return false, ""
	}
	// 完整程序身份：进程名、PID、服务、程序路径、EUID、能力缺一不可
	found, detail := hit([]facts.Fact{proc(map[string]string{
		"role": "nonroot-with-caps", "comm": "sshd", "exe": "/usr/sbin/sshd",
		"unit": "sshd.service", "euid": "1000", "caps": "[CAP_AUDIT_CONTROL]",
	})})
	if !found {
		t.Fatal("高能力进程未被检出")
	}
	if want := "进程 sshd（PID 609，服务 sshd.service，程序 /usr/sbin/sshd）以非 root 身份（EUID 1000）持有能力：[CAP_AUDIT_CONTROL]"; detail != want {
		t.Fatalf("文案不符：got %q want %q", detail, want)
	}
	// 缺失项省略，不留空括号
	found, detail = hit([]facts.Fact{proc(map[string]string{
		"role": "nonroot-with-caps", "comm": "agent", "caps": "[CAP_SYS_ADMIN]",
	})})
	if !found {
		t.Fatal("缺失项进程未被检出")
	}
	if want := "进程 agent（PID 609）以非 root 身份持有能力：[CAP_SYS_ADMIN]"; detail != want {
		t.Fatalf("文案不符：got %q want %q", detail, want)
	}
	// 基线仍按 Subject + caps 键豁免，不受文案影响
	bl := &Baseline{Allows: []BaselineAllow{
		{Subject: "kf7/bootid/609/1795", Kind: "identity", Value: "caps:[CAP_SYS_ADMIN]"},
	}}
	for _, r := range DefaultRegistry().Evaluate(testBundle(facts.TargetOSLinux, []facts.Fact{proc(map[string]string{
		"role": "nonroot-with-caps", "comm": "agent", "caps": "[CAP_SYS_ADMIN]",
	})}), bl) {
		if r.RuleID == "os.linux.high_capabilities" && r.Conclusion == facts.ConclusionFail {
			t.Fatal("基线豁免失效")
		}
	}
}

func TestOracleAnyPrivilegeDBAExempt(t *testing.T) {
	// M35：DBA 角色是 Oracle 内置管理角色，其管理权限属固有权限，不报警。
	priv := func(subject, privilege string) facts.Fact {
		return facts.Fact{FactID: "f-p1", Kind: facts.FactPrivilege, Subject: subject,
			Status: facts.StatusObserved, Attributes: map[string]string{"privilege": privilege}}
	}
	hit := func(fs []facts.Fact) bool {
		for _, r := range DefaultRegistry().Evaluate(testBundle(facts.TargetDBOracle, fs), &Baseline{}) {
			if r.RuleID == "db.oracle.any_privilege" && r.Conclusion == facts.ConclusionFail {
				return true
			}
		}
		return false
	}
	if hit([]facts.Fact{priv("DBA", "ADMINISTER ANY SQL TUNING SET")}) {
		t.Fatal("DBA 角色的 ANY 权限仍在报警")
	}
	if hit([]facts.Fact{priv("dba", "CREATE ANY TABLE")}) {
		t.Fatal("小写 dba 仍在报警（应大小写不敏感）")
	}
	if !hit([]facts.Fact{priv("SYS", "ADMINISTER ANY SQL TUNING SET")}) {
		t.Fatal("非 DBA 主体的 ANY 权限未被检出")
	}
	if !hit([]facts.Fact{priv("APP_USER", "SELECT ANY TABLE")}) {
		t.Fatal("普通用户的 ANY 权限未被检出")
	}
	if hit([]facts.Fact{priv("DBA", "CREATE SESSION")}) {
		t.Fatal("非 ANY 权限被误报")
	}
}

func TestLinuxRootMismatch(t *testing.T) {
	proc := func(attrs map[string]string) facts.Fact {
		return facts.Fact{FactID: "f-p1", Kind: facts.FactProcess, Subject: "h/boot/1/1",
			Status: facts.StatusObserved, Attributes: attrs}
	}
	hit := func(fs []facts.Fact) (bool, string) {
		for _, r := range DefaultRegistry().Evaluate(testBundle(facts.TargetOSLinux, fs), &Baseline{}) {
			if r.RuleID == "os.linux.root_mismatch" && r.Conclusion == facts.ConclusionFail {
				return true, r.Detail
			}
		}
		return false, ""
	}
	// 数值 "0" 即 root 本人（如 user@0.service），不得误报
	if found, _ := hit([]facts.Fact{proc(map[string]string{
		"configured_user": "0", "euid": "0", "comm": "systemd",
	})}); found {
		t.Fatal("configured_user=0 被误报 root_mismatch")
	}
	// 命名非 root 用户 + EUID=0 → 命中，文案含单元与配置用户
	found, detail := hit([]facts.Fact{proc(map[string]string{
		"configured_user": "app", "euid": "0", "comm": "java", "unit": "app.service",
	})})
	if !found {
		t.Fatal("命名用户不一致未被检出")
	}
	if want := "服务 app.service 配置用户 app，但进程 java 实际 EUID=0"; detail != want {
		t.Fatalf("文案不符：got %q want %q", detail, want)
	}
	// 数值非 root uid + EUID=0 → 命中，文案以 uid 形式表述
	found, detail = hit([]facts.Fact{proc(map[string]string{
		"configured_user": "1000", "euid": "0", "comm": "svc",
	})})
	if !found {
		t.Fatal("数值 uid 不一致未被检出")
	}
	if want := "进程 svc 配置用户 uid 1000，但实际 EUID=0"; detail != want {
		t.Fatalf("文案不符：got %q want %q", detail, want)
	}
}

func failsFor(t *testing.T, b *facts.FactBundle, ruleID string) []TechnicalResult {
	t.Helper()
	var out []TechnicalResult
	for _, r := range DefaultRegistry().Evaluate(b, &Baseline{}) {
		if r.RuleID == ruleID && r.Conclusion == facts.ConclusionFail {
			out = append(out, r)
		}
	}
	return out
}

func TestPGSSLAndAudit(t *testing.T) {
	pg := func(name, setting string) facts.Fact {
		return facts.Fact{FactID: "f-" + name, Kind: facts.FactAccountConfig, Subject: "server",
			Status: facts.StatusObserved, Source: "pg.settings",
			Attributes: map[string]string{"name": name, "setting": setting}}
	}
	// ssl=off → ssl_off FAIL；三项审计信号全关 → audit_off FAIL
	b := testBundle(facts.TargetDBPostgres, []facts.Fact{
		pg("ssl", "off"), pg("logging_collector", "off"),
		pg("log_connections", "off"), pg("log_statement", "none"),
	})
	b.Receipts = []facts.Receipt{{TemplateID: "pg.settings", TemplateVersion: "1", Status: "ok"}}
	if got := failsFor(t, b, "db.pg.ssl_off"); len(got) != 1 {
		t.Fatalf("ssl_off fails = %d, want 1", len(got))
	}
	if got := failsFor(t, b, "db.pg.audit_off"); len(got) != 1 {
		t.Fatalf("audit_off fails = %d, want 1", len(got))
	}
	// ssl=on 且 logging_collector=on → 两规则均不 FAIL
	b2 := testBundle(facts.TargetDBPostgres, []facts.Fact{
		pg("ssl", "on"), pg("logging_collector", "on"),
		pg("log_connections", "off"), pg("log_statement", "none"),
	})
	b2.Receipts = []facts.Receipt{{TemplateID: "pg.settings", TemplateVersion: "1", Status: "ok"}}
	if got := failsFor(t, b2, "db.pg.ssl_off"); len(got) != 0 {
		t.Fatalf("ssl=on 时 ssl_off 不应 FAIL，got %d", len(got))
	}
	if got := failsFor(t, b2, "db.pg.audit_off"); len(got) != 0 {
		t.Fatalf("logging_collector=on 时 audit_off 不应 FAIL，got %d", len(got))
	}
	// 仅 log_statement=ddl 也算审计开启
	b3 := testBundle(facts.TargetDBPostgres, []facts.Fact{
		pg("ssl", "on"), pg("logging_collector", "off"),
		pg("log_connections", "off"), pg("log_statement", "ddl"),
	})
	b3.Receipts = []facts.Receipt{{TemplateID: "pg.settings", TemplateVersion: "1", Status: "ok"}}
	if got := failsFor(t, b3, "db.pg.audit_off"); len(got) != 0 {
		t.Fatalf("log_statement=ddl 时 audit_off 不应 FAIL，got %d", len(got))
	}
}

func TestMySQLPasswordPolicy(t *testing.T) {
	mv := func(name, value string) facts.Fact {
		return facts.Fact{FactID: "f-" + name, Kind: facts.FactAccountConfig, Subject: "global",
			Status: facts.StatusObserved, Source: "mysql.server_config",
			Attributes: map[string]string{"name": name, "value": value}}
	}
	b := testBundle(facts.TargetDBMySQL, []facts.Fact{
		mv("validate_password.policy", "LOW"), mv("validate_password.length", "6"),
	})
	b.Receipts = []facts.Receipt{{TemplateID: "mysql.server_config", TemplateVersion: "1", Status: "ok"}}
	if got := failsFor(t, b, "db.mysql.password_policy"); len(got) != 2 {
		t.Fatalf("LOW+6 位时 password_policy fails = %d, want 2", len(got))
	}
	b2 := testBundle(facts.TargetDBMySQL, []facts.Fact{
		mv("validate_password.policy", "MEDIUM"), mv("validate_password.length", "12"),
	})
	b2.Receipts = []facts.Receipt{{TemplateID: "mysql.server_config", TemplateVersion: "1", Status: "ok"}}
	if got := failsFor(t, b2, "db.mysql.password_policy"); len(got) != 0 {
		t.Fatalf("MEDIUM+12 位时不应 FAIL，got %d", len(got))
	}
	// 未采集到 validate_password 变量时结论为 UNKNOWN，不误报 FAIL（老包不误报）
	b3 := testBundle(facts.TargetDBMySQL, []facts.Fact{mv("general_log", "OFF")})
	b3.Receipts = []facts.Receipt{{TemplateID: "mysql.server_config", TemplateVersion: "1", Status: "ok"}}
	if got := failsFor(t, b3, "db.mysql.password_policy"); len(got) != 0 {
		t.Fatalf("无 validate_password 事实时不应 FAIL，got %d", len(got))
	}
}

func TestMSSQLPasswordPolicy(t *testing.T) {
	login := func(name, ptype, disabled, policy, expir string) facts.Fact {
		return facts.Fact{FactID: "f-" + name, Kind: facts.FactIdentity, Subject: name,
			Status: facts.StatusObserved, Source: "mssql.server_principals",
			Attributes: map[string]string{
				"principal_type": ptype, "is_disabled": disabled,
				"is_policy_checked": policy, "is_expiration_checked": expir,
			}}
	}
	b := testBundle(facts.TargetDBSQLSrv, []facts.Fact{
		login("app", "SQL_LOGIN", "false", "false", "false"),
		login("svc", "SQL_LOGIN", "false", "true", "true"),
		login("dom\\user", "WINDOWS_LOGIN", "false", "false", "false"),
		login("old", "SQL_LOGIN", "true", "false", "false"),
	})
	b.Receipts = []facts.Receipt{{TemplateID: "mssql.server_principals", TemplateVersion: "1", Status: "ok"}}
	if got := failsFor(t, b, "db.mssql.password_policy"); len(got) != 2 {
		t.Fatalf("password_policy fails = %d, want 2（仅 app 的两项）", len(got))
	}
}

func TestOracleProfileVerifyFunction(t *testing.T) {
	prof := func(profile, res, lim string) facts.Fact {
		return facts.Fact{FactID: "f-" + profile + "-" + res, Kind: facts.FactAccountConfig,
			Subject: profile, Status: facts.StatusObserved, Source: "ora.profiles",
			Attributes: map[string]string{"resource": res, "limit": lim}}
	}
	b := testBundle(facts.TargetDBOracle, []facts.Fact{
		prof("DEFAULT", "PASSWORD_VERIFY_FUNCTION", ""),
		prof("APP_PROFILE", "PASSWORD_VERIFY_FUNCTION", "ora12c_verify_function"),
		prof("DEFAULT", "PASSWORD_LIFE_TIME", "UNLIMITED"),
	})
	if got := failsFor(t, b, "db.oracle.profile_password_policy"); len(got) != 2 {
		t.Fatalf("profile_password_policy fails = %d, want 2（空验证函数 + UNLIMITED 寿命）", len(got))
	}
}

func TestOracleAuditTrail(t *testing.T) {
	param := func(value string) facts.Fact {
		return facts.Fact{FactID: "f-audit", Kind: facts.FactAccountConfig, Subject: "AUDIT_TRAIL",
			Status: facts.StatusObserved, Source: "ora.parameters",
			Attributes: map[string]string{"name": "AUDIT_TRAIL", "value": value}}
	}
	bNone := testBundle(facts.TargetDBOracle, []facts.Fact{param("NONE")})
	bNone.Receipts = []facts.Receipt{{TemplateID: "ora.parameters", TemplateVersion: "1", Status: "ok"}}
	if got := failsFor(t, bNone, "db.oracle.audit_trail_off"); len(got) != 1 {
		t.Fatalf("AUDIT_TRAIL=NONE 时 fails = %d, want 1", len(got))
	}
	bDB := testBundle(facts.TargetDBOracle, []facts.Fact{param("DB")})
	bDB.Receipts = []facts.Receipt{{TemplateID: "ora.parameters", TemplateVersion: "1", Status: "ok"}}
	if got := failsFor(t, bDB, "db.oracle.audit_trail_off"); len(got) != 0 {
		t.Fatalf("AUDIT_TRAIL=DB 时不应 FAIL，got %d", len(got))
	}
}

func TestMSSQLAudit(t *testing.T) {
	audit := func(name, enabled string) facts.Fact {
		return facts.Fact{FactID: "f-" + name, Kind: facts.FactAccountConfig, Subject: name,
			Status: facts.StatusObserved, Source: "mssql.server_audits",
			Attributes: map[string]string{"is_state_enabled": enabled}}
	}
	cfg := facts.Fact{FactID: "f-cfg", Kind: facts.FactAccountConfig, Subject: "xp_cmdshell",
		Status: facts.StatusObserved, Source: "mssql.server_config",
		Attributes: map[string]string{"value_in_use": "0"}}
	b := testBundle(facts.TargetDBSQLSrv, []facts.Fact{cfg, audit("audit1", "false")})
	b.Receipts = []facts.Receipt{{TemplateID: "mssql.server_audits", TemplateVersion: "1", Status: "ok"}}
	if got := failsFor(t, b, "db.mssql.audit_off"); len(got) != 1 {
		t.Fatalf("无启用审计时 fails = %d, want 1", len(got))
	}
	b2 := testBundle(facts.TargetDBSQLSrv, []facts.Fact{cfg, audit("audit1", "false"), audit("audit2", "true")})
	b2.Receipts = []facts.Receipt{{TemplateID: "mssql.server_audits", TemplateVersion: "1", Status: "ok"}}
	if got := failsFor(t, b2, "db.mssql.audit_off"); len(got) != 0 {
		t.Fatalf("有启用审计时不应 FAIL，got %d", len(got))
	}
}

func TestLinuxSshRules(t *testing.T) {
	sshd := func(pa, prl, present string) facts.Fact {
		return facts.Fact{FactID: "f-sshd", Kind: facts.FactAccountConfig, Subject: "sshd_config",
			Status: facts.StatusObserved, Source: "linux.sshd",
			Attributes: map[string]string{"present": present,
				"password_authentication": pa, "permit_root_login": prl}}
	}
	b := testBundle(facts.TargetOSLinux, []facts.Fact{sshd("yes", "yes", "true")})
	b.Receipts = []facts.Receipt{{TemplateID: "linux.sshd", TemplateVersion: "1", Status: "ok"}}
	if got := failsFor(t, b, "os.linux.ssh_password_auth"); len(got) != 1 {
		t.Fatalf("password_auth=yes 时 fails = %d, want 1", len(got))
	}
	if got := failsFor(t, b, "os.linux.ssh_root_login"); len(got) != 1 {
		t.Fatalf("root_login=yes 时 fails = %d, want 1", len(got))
	}
	// 缺省口令鉴别（空值）按 sshd 缺省 yes 判；prohibit-password 不判 root 登录
	b2 := testBundle(facts.TargetOSLinux, []facts.Fact{sshd("", "prohibit-password", "true")})
	b2.Receipts = []facts.Receipt{{TemplateID: "linux.sshd", TemplateVersion: "1", Status: "ok"}}
	if got := failsFor(t, b2, "os.linux.ssh_password_auth"); len(got) != 1 {
		t.Fatalf("口令鉴别缺省时 fails = %d, want 1", len(got))
	}
	if got := failsFor(t, b2, "os.linux.ssh_root_login"); len(got) != 0 {
		t.Fatalf("prohibit-password 时不应 FAIL，got %d", len(got))
	}
	// 全关与文件缺失均不判
	b3 := testBundle(facts.TargetOSLinux, []facts.Fact{sshd("no", "no", "true")})
	b3.Receipts = []facts.Receipt{{TemplateID: "linux.sshd", TemplateVersion: "1", Status: "ok"}}
	if got := failsFor(t, b3, "os.linux.ssh_password_auth"); len(got) != 0 {
		t.Fatalf("全关时 password_auth 不应 FAIL，got %d", len(got))
	}
	// 文件缺失（采集器发 StatusUnsupported 事实）→ NOT_APPLICABLE，不是 PASS
	b4 := testBundle(facts.TargetOSLinux, []facts.Fact{{
		FactID: "f-sshd", Kind: facts.FactAccountConfig, Subject: "sshd_config",
		Status: facts.StatusUnsupported, Source: "linux.sshd",
		Attributes: map[string]string{"present": "false"},
	}})
	b4.Receipts = []facts.Receipt{{TemplateID: "linux.sshd", TemplateVersion: "1", Status: "ok"}}
	if got := failsFor(t, b4, "os.linux.ssh_password_auth"); len(got) != 0 {
		t.Fatalf("文件缺失时不应 FAIL，got %d", len(got))
	}
	if r := singleResult(t, b4, &Baseline{}, "os.linux.ssh_password_auth"); r.Conclusion != facts.ConclusionNotApplicable {
		t.Fatalf("文件缺失时应为 NOT_APPLICABLE，实际 %s", r.Conclusion)
	}
}
