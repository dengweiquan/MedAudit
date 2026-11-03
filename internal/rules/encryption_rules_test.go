package rules

import (
	"testing"

	"medaudit/internal/facts"
)

func sqlnetFact(home, enc string, extra map[string]string) facts.Fact {
	attrs := map[string]string{"oracle_home": home, "sid": "ORCL", "sqlnet_file": home + "/network/admin/sqlnet.ora"}
	if enc != "" {
		attrs["encryption_server"] = enc
	}
	for k, v := range extra {
		attrs[k] = v
	}
	return facts.Fact{FactID: "f-sqlnet", Kind: facts.FactAccountConfig, Subject: home,
		Status: facts.StatusObserved, Source: "linux.oracle_sqlnet", Attributes: attrs}
}

func sqlnetBundle(fs []facts.Fact, status string) *facts.FactBundle {
	return testBundleR(facts.TargetOSLinux, fs,
		[]facts.Receipt{{TemplateID: "linux.oracle_sqlnet", TemplateVersion: "1", Status: status}})
}

func TestOracleNativeEncryption(t *testing.T) {
	req := sqlnetBundle([]facts.Fact{sqlnetFact("/u01/dbhome", "required", nil)}, "ok")
	r := singleResult(t, req, &Baseline{}, "os.linux.oracle_native_encryption_not_required")
	expectConclusion(t, r, facts.ConclusionPass)

	acc := sqlnetBundle([]facts.Fact{sqlnetFact("/u01/dbhome", "accepted", nil)}, "ok")
	r = singleResult(t, acc, &Baseline{}, "os.linux.oracle_native_encryption_not_required")
	expectConclusion(t, r, facts.ConclusionFail)

	// 文件缺失取缺省 accepted → FAIL，且明细注明缺省。
	missing := sqlnetBundle([]facts.Fact{sqlnetFact("/u01/dbhome", "accepted",
		map[string]string{"file_missing": "true"})}, "ok")
	r = singleResult(t, missing, &Baseline{}, "os.linux.oracle_native_encryption_not_required")
	expectConclusion(t, r, facts.ConclusionFail)

	// 宿主无 Oracle Home → 不适用。
	noHome := testBundleR(facts.TargetOSLinux, []facts.Fact{{
		FactID: "f-inv", Kind: facts.FactAccountConfig, Subject: "oracle-homes",
		Status: facts.StatusObserved, Source: "linux.oracle_sqlnet",
		Attributes: map[string]string{"oracle_homes": "0"},
	}}, []facts.Receipt{{TemplateID: "linux.oracle_sqlnet", TemplateVersion: "1", Status: "ok"}})
	r = singleResult(t, noHome, &Baseline{}, "os.linux.oracle_native_encryption_not_required")
	expectConclusion(t, r, facts.ConclusionNotApplicable)

	// 文件不可读（PermissionDenied 事实 + partial 收据）→ UNKNOWN。
	denied := testBundleR(facts.TargetOSLinux, []facts.Fact{{
		FactID: "f-den", Kind: facts.FactAccountConfig, Subject: "/u01/dbhome",
		Status: facts.StatusPermissionDenied, Source: "linux.oracle_sqlnet",
		Attributes: map[string]string{"oracle_home": "/u01/dbhome"},
	}}, []facts.Receipt{{TemplateID: "linux.oracle_sqlnet", TemplateVersion: "1", Status: "partial"}})
	r = singleResult(t, denied, &Baseline{}, "os.linux.oracle_native_encryption_not_required")
	expectConclusion(t, r, facts.ConclusionUnknown)

	// 旧包（无收据无事实）→ UNKNOWN。
	legacy := testBundleR(facts.TargetOSLinux, nil, nil)
	r = singleResult(t, legacy, &Baseline{}, "os.linux.oracle_native_encryption_not_required")
	expectConclusion(t, r, facts.ConclusionUnknown)
}

func mssqlFact(inst, val string, extra map[string]string) facts.Fact {
	attrs := map[string]string{"instance_id": "MSSQL13.MSSQLSERVER", "effective": "unknown"}
	if val != "" {
		attrs["force_encryption"] = val
	}
	for k, v := range extra {
		attrs[k] = v
	}
	return facts.Fact{FactID: "f-ms", Kind: facts.FactAccountConfig, Subject: inst,
		Status: facts.StatusObserved, Source: "win.mssql_force_encryption", Attributes: attrs}
}

func mssqlBundle(fs []facts.Fact, status string) *facts.FactBundle {
	return testBundleR(facts.TargetOSWindows, fs,
		[]facts.Receipt{{TemplateID: "win.mssql_force_encryption", TemplateVersion: "1", Status: status}})
}

func TestMSSQLForceEncryption(t *testing.T) {
	on := mssqlBundle([]facts.Fact{mssqlFact("MSSQLSERVER", "1", nil)}, "ok")
	r := singleResult(t, on, &Baseline{}, "os.windows.mssql_force_encryption_off")
	expectConclusion(t, r, facts.ConclusionPass)

	off := mssqlBundle([]facts.Fact{mssqlFact("MSSQLSERVER", "0", nil)}, "ok")
	r = singleResult(t, off, &Baseline{}, "os.windows.mssql_force_encryption_off")
	expectConclusion(t, r, facts.ConclusionFail)

	// 值缺失取缺省 0 → FAIL。
	missing := mssqlBundle([]facts.Fact{mssqlFact("MSSQLSERVER", "0",
		map[string]string{"value_missing": "true"})}, "ok")
	r = singleResult(t, missing, &Baseline{}, "os.windows.mssql_force_encryption_off")
	expectConclusion(t, r, facts.ConclusionFail)

	// 宿主无实例 → 不适用。
	noInst := testBundleR(facts.TargetOSWindows, []facts.Fact{{
		FactID: "f-inv", Kind: facts.FactAccountConfig, Subject: "mssql-instances",
		Status: facts.StatusObserved, Source: "win.mssql_force_encryption",
		Attributes: map[string]string{"mssql_instances": "0"},
	}}, []facts.Receipt{{TemplateID: "win.mssql_force_encryption", TemplateVersion: "1", Status: "ok"}})
	r = singleResult(t, noInst, &Baseline{}, "os.windows.mssql_force_encryption_off")
	expectConclusion(t, r, facts.ConclusionNotApplicable)

	// 枚举失败（收据 denied）→ UNKNOWN。
	failed := mssqlBundle(nil, "denied")
	r = singleResult(t, failed, &Baseline{}, "os.windows.mssql_force_encryption_off")
	expectConclusion(t, r, facts.ConclusionUnknown)

	// 一实例可读 FAIL + 一实例不可读：可读实例照常判 FAIL，不被不可读实例掩盖。
	mixed := testBundleR(facts.TargetOSWindows, []facts.Fact{
		mssqlFact("MSSQLSERVER", "0", nil),
		{FactID: "f-den", Kind: facts.FactAccountConfig, Subject: "SQLEXPRESS",
			Status: facts.StatusPermissionDenied, Source: "win.mssql_force_encryption",
			Attributes: map[string]string{"instance_id": "MSSQL13.SQLEXPRESS"}},
	}, []facts.Receipt{{TemplateID: "win.mssql_force_encryption", TemplateVersion: "1", Status: "ok"}})
	rs := resultsFor(t, mixed, &Baseline{}, "os.windows.mssql_force_encryption_off")
	if len(rs) != 1 || rs[0].Conclusion != facts.ConclusionFail || rs[0].Subject != "MSSQLSERVER" {
		t.Fatalf("want single FAIL for MSSQLSERVER, got %+v", rs)
	}
}
