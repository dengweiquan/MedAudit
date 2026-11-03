package rules

import (
	"testing"

	"medaudit/internal/facts"
)

// 静态复核回归：证据门控不得被“安全”事实绕过、不得只核对键名不验证值、
// 不得把部分采集读成通过。

// SSH：安全的 Observed 事实 + 无收据/失败收据/截断收据 → UNKNOWN，绝不 PASS。
func TestReviewSSHSecureFactBadReceipt(t *testing.T) {
	secure := []facts.Fact{{
		FactID: "f1", Kind: facts.FactAccountConfig, Subject: "sshd_config",
		Status: facts.StatusObserved, Source: "linux.sshd",
		Attributes: map[string]string{"present": "true", "password_authentication": "no", "permit_root_login": "no"},
	}}
	cases := []struct {
		name string
		rcs  []facts.Receipt
	}{
		{"无收据", nil},
		{"失败收据", []facts.Receipt{receipt("linux.sshd", "failed")}},
		{"截断收据", []facts.Receipt{{TemplateID: "linux.sshd", TemplateVersion: "1", Status: "partial"}}},
	}
	for _, tc := range cases {
		b := testBundleR(facts.TargetOSLinux, secure, tc.rcs)
		for _, id := range []string{"os.linux.ssh_password_auth", "os.linux.ssh_root_login"} {
			r := singleResult(t, b, &Baseline{}, id)
			expectConclusion(t, r, facts.ConclusionUnknown)
		}
	}
	// 对照：收据 ok 时安全事实 → PASS。
	b := testBundleR(facts.TargetOSLinux, secure, []facts.Receipt{receipt("linux.sshd", "ok")})
	for _, id := range []string{"os.linux.ssh_password_auth", "os.linux.ssh_root_login"} {
		r := singleResult(t, b, &Baseline{}, id)
		expectConclusion(t, r, facts.ConclusionPass)
	}
}

// PG SSL：setting 缺失/非法 → UNKNOWN；on → PASS；off → FAIL。
func TestReviewPGSSLValueValidation(t *testing.T) {
	mk := func(setting string) *facts.FactBundle {
		return testBundleR(facts.TargetDBPostgres, []facts.Fact{{
			FactID: "f1", Kind: facts.FactAccountConfig, Subject: "server",
			Status: facts.StatusObserved, Source: "pg.settings",
			Attributes: map[string]string{"name": "ssl", "setting": setting},
		}}, []facts.Receipt{receipt("pg.settings", "ok")})
	}
	for _, tc := range []struct {
		setting string
		want    facts.Conclusion
	}{
		{"", facts.ConclusionUnknown},
		{"bogus", facts.ConclusionUnknown},
		{"on", facts.ConclusionPass},
		{"off", facts.ConclusionFail},
		{"false", facts.ConclusionFail},
		{"no", facts.ConclusionFail},
		{"0", facts.ConclusionFail},
		{" off ", facts.ConclusionFail},
		{"OFF", facts.ConclusionFail},
		{"true", facts.ConclusionPass},
	} {
		r := singleResult(t, mk(tc.setting), &Baseline{}, "db.pg.ssl_off")
		expectConclusion(t, r, tc.want)
	}
}

// Oracle AUDIT_TRAIL：value 缺失/非法 → UNKNOWN；DB → PASS；NONE → FAIL。
func TestReviewOracleAuditTrailValueValidation(t *testing.T) {
	mk := func(value string) *facts.FactBundle {
		return testBundleR(facts.TargetDBOracle, []facts.Fact{{
			FactID: "f1", Kind: facts.FactAccountConfig, Subject: "server",
			Status: facts.StatusObserved, Source: "ora.parameters",
			Attributes: map[string]string{"name": "AUDIT_TRAIL", "value": value},
		}}, []facts.Receipt{receipt("ora.parameters", "ok")})
	}
	for _, tc := range []struct {
		value string
		want  facts.Conclusion
	}{
		{"", facts.ConclusionUnknown},
		{"BOGUS", facts.ConclusionUnknown},
		{"DB", facts.ConclusionPass},
		{"NONE", facts.ConclusionFail},
		{" NONE ", facts.ConclusionFail},
		{"none", facts.ConclusionFail},
		{"db", facts.ConclusionPass},
	} {
		r := singleResult(t, mk(tc.value), &Baseline{}, "db.oracle.audit_trail_off")
		expectConclusion(t, r, tc.want)
	}
}

// MySQL 口令策略：策略与长度须同时合法才可完整判定；
// 但单项已是确定违规（策略 LOW，或长度 <8）时不必等另一项——违规本身即可判 FAIL。
func TestReviewMySQLPasswordBothRequired(t *testing.T) {
	mk := func(fs []facts.Fact) *facts.FactBundle {
		return testBundleR(facts.TargetDBMySQL, fs, []facts.Receipt{receipt("mysql.server_config", "ok")})
	}
	policy := func(v string) facts.Fact {
		return facts.Fact{FactID: "p", Kind: facts.FactAccountConfig, Subject: "global",
			Status: facts.StatusObserved, Source: "mysql.server_config",
			Attributes: map[string]string{"name": "validate_password.policy", "value": v}}
	}
	length := func(v string) facts.Fact {
		return facts.Fact{FactID: "l", Kind: facts.FactAccountConfig, Subject: "global",
			Status: facts.StatusObserved, Source: "mysql.server_config",
			Attributes: map[string]string{"name": "validate_password.length", "value": v}}
	}
	for _, tc := range []struct {
		name string
		fs   []facts.Fact
		want facts.Conclusion
	}{
		{"仅策略", []facts.Fact{policy("MEDIUM")}, facts.ConclusionUnknown},
		{"仅长度", []facts.Fact{length("8")}, facts.ConclusionUnknown},
		{"长度非法", []facts.Fact{policy("MEDIUM"), length("bogus")}, facts.ConclusionUnknown},
		{"策略非法", []facts.Fact{policy("WEAK"), length("8")}, facts.ConclusionUnknown},
		{"双项合法", []facts.Fact{policy("MEDIUM"), length("8")}, facts.ConclusionPass},
		{"策略弱", []facts.Fact{policy("LOW"), length("8")}, facts.ConclusionFail},
		{"长度不足", []facts.Fact{policy("MEDIUM"), length("4")}, facts.ConclusionFail},
		{"策略弱无长度（确定违规）", []facts.Fact{policy("LOW")}, facts.ConclusionFail},
		{"无策略长度不足（确定违规）", []facts.Fact{length("4")}, facts.ConclusionFail},
		// 静态复核回归三轮：门控与检查共用规范化——带空格的 LOW 不得 Ready 后无命中而 PASS。
		{"策略带空格弱无长度", []facts.Fact{policy(" LOW ")}, facts.ConclusionFail},
		{"策略带空格弱有长度", []facts.Fact{policy(" LOW "), length("12")}, facts.ConclusionFail},
		{"策略带空格合法", []facts.Fact{policy(" MEDIUM "), length("8")}, facts.ConclusionPass},
	} {
		r := singleResult(t, mk(tc.fs), &Baseline{}, "db.mysql.password_policy")
		if r.Conclusion != tc.want {
			t.Errorf("%s: want %s, got %s", tc.name, tc.want, r.Conclusion)
		}
	}
}

// Windows 口令数值：属性存在但不可解析 → UNKNOWN（不得因 check 跳过而 PASS）。
func TestReviewWinPasswordUnparseable(t *testing.T) {
	mk := func(v string) *facts.FactBundle {
		return testBundleR(facts.TargetOSWindows, []facts.Fact{{
			FactID: "f1", Kind: facts.FactAccountConfig, Subject: "password-policy",
			Status: facts.StatusObserved, Source: "win.password_policy",
			Attributes: map[string]string{"min_password_length": v, "scope": "local-sam", "machine_role": "workgroup"},
		}}, []facts.Receipt{receipt("win.password_policy", "ok")})
	}
	for _, tc := range []struct {
		v    string
		want facts.Conclusion
	}{
		{"bogus", facts.ConclusionUnknown},
		{"", facts.ConclusionUnknown},
		{"4", facts.ConclusionFail},
		{" 4 ", facts.ConclusionFail},
		{"12", facts.ConclusionPass},
	} {
		r := singleResult(t, mk(tc.v), &Baseline{}, "os.windows.password_min_length")
		expectConclusion(t, r, tc.want)
	}
}

// MSSQL ForceEncryption 门控：部分采集时已有违规仍 FAIL、无命中则 UNKNOWN；
// 收据失败时不得被“无实例”盘点事实掩盖为不适用。
func TestReviewMSSQLForceEncryptionPartial(t *testing.T) {
	on := facts.Fact{FactID: "f1", Kind: facts.FactAccountConfig, Subject: "MSSQLSERVER",
		Status: facts.StatusObserved, Source: "win.mssql_force_encryption",
		Attributes: map[string]string{"force_encryption": "1"}}
	off := facts.Fact{FactID: "f2", Kind: facts.FactAccountConfig, Subject: "SQLEXPRESS",
		Status: facts.StatusObserved, Source: "win.mssql_force_encryption",
		Attributes: map[string]string{"force_encryption": "0"}}
	denied := facts.Fact{FactID: "f3", Kind: facts.FactAccountConfig, Subject: "OTHER",
		Status: facts.StatusPermissionDenied, Source: "win.mssql_force_encryption",
		Attributes: map[string]string{"error": "denied"}}
	noInst := facts.Fact{FactID: "f0", Kind: facts.FactAccountConfig, Subject: "mssql-instances",
		Status: facts.StatusObserved, Source: "win.mssql_force_encryption",
		Attributes: map[string]string{"mssql_instances": "0"}}
	partial := facts.Receipt{TemplateID: "win.mssql_force_encryption", TemplateVersion: "1", Status: "partial"}
	// 部分采集 + 仅开启实例 → UNKNOWN（不可读实例可能是违规的）。
	b := testBundleR(facts.TargetOSWindows, []facts.Fact{on, denied}, []facts.Receipt{partial})
	expectConclusion(t, singleResult(t, b, &Baseline{}, "os.windows.mssql_force_encryption_off"), facts.ConclusionUnknown)
	// 部分采集 + 有关闭实例 → FAIL（明确违规不被掩盖）。
	b = testBundleR(facts.TargetOSWindows, []facts.Fact{on, off, denied}, []facts.Receipt{partial})
	expectConclusion(t, singleResult(t, b, &Baseline{}, "os.windows.mssql_force_encryption_off"), facts.ConclusionFail)
	// 收据 ok + 无实例 → 不适用。
	b = testBundleR(facts.TargetOSWindows, []facts.Fact{noInst}, []facts.Receipt{receipt("win.mssql_force_encryption", "ok")})
	expectConclusion(t, singleResult(t, b, &Baseline{}, "os.windows.mssql_force_encryption_off"), facts.ConclusionNotApplicable)
	// 收据失败 + 无实例盘点事实 → UNKNOWN（收据先行，不得掩盖为不适用）。
	b = testBundleR(facts.TargetOSWindows, []facts.Fact{noInst}, []facts.Receipt{receipt("win.mssql_force_encryption", "denied")})
	expectConclusion(t, singleResult(t, b, &Baseline{}, "os.windows.mssql_force_encryption_off"), facts.ConclusionUnknown)
	// 收据 ok + 仅开启实例 → PASS。
	b = testBundleR(facts.TargetOSWindows, []facts.Fact{on}, []facts.Receipt{receipt("win.mssql_force_encryption", "ok")})
	expectConclusion(t, singleResult(t, b, &Baseline{}, "os.windows.mssql_force_encryption_off"), facts.ConclusionPass)
}

// 静态复核回归二轮：门控与规则共用解析——Windows 最大期限与锁定阈值。
// 带空格的永不过期值必须命中；超 uint32 的越界值与负值门控不放行 → UNKNOWN；
// 带空格的 0 锁定阈值必须命中（锁定关闭）。
func TestReviewWinPasswordSharedParsing(t *testing.T) {
	mk := func(attrs map[string]string) *facts.FactBundle {
		base := map[string]string{"scope": "local-sam", "machine_role": "workgroup"}
		for k, v := range attrs {
			base[k] = v
		}
		return testBundleR(facts.TargetOSWindows, []facts.Fact{{
			FactID: "f1", Kind: facts.FactAccountConfig, Subject: "password-policy",
			Status: facts.StatusObserved, Source: "win.password_policy",
			Attributes: base,
		}}, []facts.Receipt{receipt("win.password_policy", "ok")})
	}
	for _, tc := range []struct {
		rule string
		attr string
		v    string
		want facts.Conclusion
	}{
		{"os.windows.password_max_age_never", "max_password_age_sec", "4294967295", facts.ConclusionFail},
		{"os.windows.password_max_age_never", "max_password_age_sec", " 4294967295 ", facts.ConclusionFail},
		{"os.windows.password_max_age_never", "max_password_age_sec", "5000000000", facts.ConclusionUnknown},
		{"os.windows.password_max_age_never", "max_password_age_sec", "-1", facts.ConclusionUnknown},
		{"os.windows.password_max_age_never", "max_password_age_sec", "86400", facts.ConclusionPass},
		{"os.windows.password_lockout_disabled", "lockout_threshold", "0", facts.ConclusionFail},
		{"os.windows.password_lockout_disabled", "lockout_threshold", " 0 ", facts.ConclusionFail},
		{"os.windows.password_lockout_disabled", "lockout_threshold", "5", facts.ConclusionPass},
		// 静态复核回归三轮：长度与锁定阈值改用 uint32 解析——负值与超 uint32
		// 的非法事实门控不放行 → UNKNOWN，不得因 check 跳过而 PASS。
		{"os.windows.password_min_length", "min_password_length", "-1", facts.ConclusionUnknown},
		{"os.windows.password_min_length", "min_password_length", "4294967296", facts.ConclusionUnknown},
		{"os.windows.password_min_length", "min_password_length", " 7 ", facts.ConclusionFail},
		{"os.windows.password_lockout_disabled", "lockout_threshold", "-1", facts.ConclusionUnknown},
		{"os.windows.password_lockout_disabled", "lockout_threshold", "4294967296", facts.ConclusionUnknown},
	} {
		r := singleResult(t, mk(map[string]string{tc.attr: tc.v}), &Baseline{}, tc.rule)
		expectConclusion(t, r, tc.want)
	}
}
