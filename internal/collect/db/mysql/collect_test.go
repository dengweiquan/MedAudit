package mysql

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"medaudit/internal/facts"
)

// TestCollectLive 对 M1 测试 MySQL 实例运行完整采集。
// 需要环境变量：MEDAUDIT_TEST_MYSQL_HOST/PORT/USER/PASS。
func TestCollectLive(t *testing.T) {
	host := os.Getenv("MEDAUDIT_TEST_MYSQL_HOST")
	user := os.Getenv("MEDAUDIT_TEST_MYSQL_USER")
	pass := os.Getenv("MEDAUDIT_TEST_MYSQL_PASS")
	if host == "" || user == "" {
		t.Skip("MEDAUDIT_TEST_MYSQL_* 未设置，跳过真实采集")
	}
	port := 3306
	if p := os.Getenv("MEDAUDIT_TEST_MYSQL_PORT"); p != "" {
		var err error
		port, err = strconv.Atoi(p)
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg := Config{
		Host: host, Port: port, User: user, Password: pass,
		ConnectTimeout: 10 * time.Second, QueryTimeout: 30 * time.Second,
	}
	b, err := Collect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if errs := b.Validate(); len(errs) != 0 {
		t.Fatalf("bundle validate: %v", errs)
	}
	t.Logf("execution=%s facts=%d receipts=%d", b.Execution, len(b.Facts), len(b.Receipts))

	// 模板收据覆盖检查。
	wantTemplates := map[string]bool{
		"mysql.accounts": false, "mysql.user_privs": false, "mysql.global_grants": false,
		"mysql.db_privs": false, "mysql.role_edges": false, "mysql.default_roles": false,
		"mysql.global_vars": false, "mysql.show_grants": false,
	}
	for _, rc := range b.Receipts {
		if _, ok := wantTemplates[rc.TemplateID]; ok {
			wantTemplates[rc.TemplateID] = true
		}
		if rc.Status != "ok" && rc.Status != "partial" {
			t.Errorf("receipt %s status = %s", rc.TemplateID, rc.Status)
		}
		t.Logf("receipt %s/%s: status=%s rows=%d duration=%dms",
			rc.TemplateID, rc.TemplateVersion, rc.Status, rc.RowCount, rc.DurationMs)
	}
	for id, seen := range wantTemplates {
		if !seen {
			t.Errorf("missing receipt for template %s", id)
		}
	}

	// 事实种类检查。
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

	// 关键语义断言（基于测试夹具）。
	assertFact := func(desc string, pred func(facts.Fact) bool) {
		for _, f := range b.Facts {
			if pred(f) {
				t.Logf("OK: %s -> %s", desc, f.FactID)
				return
			}
		}
		t.Errorf("missing: %s", desc)
	}
	assertFact("medaudit_app 的默认角色边", func(f facts.Fact) bool {
		return f.Kind == facts.FactRoleEdge && f.Subject == "medaudit_app@%" &&
			len(f.PermissionPath) == 2 && f.PermissionPath[0] == "medaudit_r_read@%" &&
			f.Activation == facts.ActivationDefault
	})
	assertFact("medaudit_app 的非默认角色边", func(f facts.Fact) bool {
		return f.Kind == facts.FactRoleEdge && f.Subject == "medaudit_app@%" &&
			len(f.PermissionPath) == 2 && f.PermissionPath[0] == "medaudit_r_extra@%" &&
			f.Activation != facts.ActivationDefault
	})
	assertFact("medaudit_app 的 WITH GRANT OPTION", func(f facts.Fact) bool {
		return f.Kind == facts.FactPrivilege && f.Subject == "medaudit_app@%" &&
			f.Attributes["privilege"] == "SELECT" && f.Scope == "medaudit_testdb.*" &&
			f.Grantable != nil && *f.Grantable
	})
	assertFact("medaudit_pr 的 partial revoke 记录", func(f facts.Fact) bool {
		return f.Kind == facts.FactPrivilege && f.Subject == "medaudit_pr@%" &&
			f.Attributes["privilege"] == "INSERT" && f.Scope == "medaudit_testdb.*" &&
			f.Attributes["revoked"] == "true"
	})
	assertFact("partial_revokes 开关事实", func(f facts.Fact) bool {
		return f.Kind == facts.FactAccountConfig && f.Subject == "global" &&
			f.Attributes["partial_revokes"] == "1"
	})

	if b.Execution != facts.ExecutionComplete {
		t.Errorf("execution = %s, want COMPLETE", b.Execution)
	}
}
