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
