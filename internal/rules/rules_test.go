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
