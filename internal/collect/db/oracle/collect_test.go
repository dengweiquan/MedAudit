package oracle

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"medaudit/internal/facts"
)

// TestCollectLive 对 M1 测试 Oracle 实例（kf03:19521/ARKPDB1）运行完整采集。
// 需要环境变量：MEDAUDIT_TEST_ORA_HOST/PORT/SERVICE/USER/PASS。
// 驱动为纯 Go（go-ora），无 CGO / Instant Client 依赖。
func TestCollectLive(t *testing.T) {
	host := os.Getenv("MEDAUDIT_TEST_ORA_HOST")
	user := os.Getenv("MEDAUDIT_TEST_ORA_USER")
	pass := os.Getenv("MEDAUDIT_TEST_ORA_PASS")
	svc := os.Getenv("MEDAUDIT_TEST_ORA_SERVICE")
	if host == "" || user == "" || svc == "" {
		t.Skip("MEDAUDIT_TEST_ORA_* 未设置，跳过真实采集")
	}
	port := 1521
	if p := os.Getenv("MEDAUDIT_TEST_ORA_PORT"); p != "" {
		var err error
		port, err = strconv.Atoi(p)
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg := Config{
		Host: host, Port: port, Service: svc, User: user, Password: pass,
		ConnectTimeout: 15 * time.Second, QueryTimeout: 30 * time.Second,
	}
	b, err := Collect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if errs := b.Validate(); len(errs) != 0 {
		t.Fatalf("bundle validate: %v", errs)
	}
	t.Logf("execution=%s facts=%d receipts=%d", b.Execution, len(b.Facts), len(b.Receipts))

	for _, tid := range []string{"ora.users", "ora.role_privs", "ora.sys_privs", "ora.tab_privs", "ora.pwfile_users"} {
		found := false
		for _, rc := range b.Receipts {
			if rc.TemplateID == tid {
				found = true
				if rc.Status != "ok" && rc.Status != "partial" {
					t.Errorf("receipt %s status = %s", tid, rc.Status)
				}
				t.Logf("receipt %s/%s: status=%s rows=%d duration=%dms",
					rc.TemplateID, rc.TemplateVersion, rc.Status, rc.RowCount, rc.DurationMs)
			}
		}
		if !found {
			t.Errorf("missing receipt for %s", tid)
		}
	}

	kinds := map[facts.FactKind]int{}
	for _, f := range b.Facts {
		kinds[f.Kind]++
	}
	for _, k := range []facts.FactKind{facts.FactPrivilege, facts.FactRoleEdge, facts.FactAccountConfig} {
		if kinds[k] == 0 {
			t.Errorf("no facts of kind %s", k)
		}
		t.Logf("kind %s: %d", k, kinds[k])
	}

	assertFact := func(desc string, pred func(facts.Fact) bool) {
		for _, f := range b.Facts {
			if pred(f) {
				t.Logf("OK: %s -> %s", desc, f.FactID)
				return
			}
		}
		t.Errorf("missing: %s", desc)
	}
	assertFact("MEDAUDIT_APP 用户事实", func(f facts.Fact) bool {
		return f.Kind == facts.FactAccountConfig && f.Subject == "MEDAUDIT_APP" &&
			f.Source == "ora.users" && f.Attributes["account_status"] == "OPEN"
	})
	assertFact("直接角色边（默认激活）", func(f facts.Fact) bool {
		return f.Kind == facts.FactRoleEdge && f.Subject == "MEDAUDIT_APP" &&
			len(f.PermissionPath) == 2 && f.PermissionPath[0] == "MEDAUDIT_R_MID" &&
			f.Activation == facts.ActivationDefault && f.Attributes["transitive"] != "true"
	})
	assertFact("直接角色边（条件激活）", func(f facts.Fact) bool {
		return f.Kind == facts.FactRoleEdge && f.Subject == "MEDAUDIT_APP" &&
			len(f.PermissionPath) == 2 && f.PermissionPath[0] == "MEDAUDIT_R_EXTRA" &&
			f.Activation == facts.ActivationConditional
	})
	assertFact("嵌套角色传递边", func(f facts.Fact) bool {
		return f.Kind == facts.FactRoleEdge && f.Subject == "MEDAUDIT_APP" &&
			f.Attributes["transitive"] == "true" &&
			len(f.PermissionPath) == 3 &&
			f.PermissionPath[0] == "MEDAUDIT_R_BASE" && f.PermissionPath[1] == "MEDAUDIT_R_MID"
	})
	assertFact("对象授权事实", func(f facts.Fact) bool {
		return f.Kind == facts.FactPrivilege && f.Subject == "MEDAUDIT_APP" &&
			f.Source == "ora.tab_privs" && f.Scope == "MEDAUDIT_OWNER.T_AUDIT" &&
			f.Attributes["privilege"] == "SELECT"
	})
	assertFact("系统权限事实", func(f facts.Fact) bool {
		return f.Kind == facts.FactPrivilege && f.Subject == "MEDAUDIT_APP" &&
			f.Source == "ora.sys_privs" && f.Attributes["privilege"] == "CREATE SESSION"
	})

	// tab_privs 预期触发行数截断（PDB 系统授权很多）：PARTIAL 合法，
	// 但不允许 failed/denied 之外的异常，且截断必须如实标记。
	for _, rc := range b.Receipts {
		if rc.Status == "failed" {
			t.Errorf("receipt %s failed", rc.TemplateID)
		}
	}
	truncOK := false
	for _, rc := range b.Receipts {
		if rc.TemplateID == "ora.tab_privs" && rc.Truncated && rc.Status == "partial" {
			truncOK = true
			t.Logf("truncation correctly marked: %s rows=%d", rc.TemplateID, rc.RowCount)
		}
	}
	if !truncOK {
		t.Errorf("expected ora.tab_privs to be marked truncated/partial")
	}
	if b.Execution != facts.ExecutionPartial && b.Execution != facts.ExecutionComplete {
		t.Errorf("execution = %s, want PARTIAL or COMPLETE", b.Execution)
	}
}
