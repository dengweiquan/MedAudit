package sqlserver

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"medaudit/internal/facts"
)

// TestCollectLive 对 M1 测试 SQL Server 实例运行完整采集。
// 需要环境变量：MEDAUDIT_TEST_MSSQL_HOST/PORT/USER/PASS。
func TestCollectLive(t *testing.T) {
	host := os.Getenv("MEDAUDIT_TEST_MSSQL_HOST")
	user := os.Getenv("MEDAUDIT_TEST_MSSQL_USER")
	pass := os.Getenv("MEDAUDIT_TEST_MSSQL_PASS")
	if host == "" || user == "" {
		t.Skip("MEDAUDIT_TEST_MSSQL_* 未设置，跳过真实采集")
	}
	port := 1433
	if p := os.Getenv("MEDAUDIT_TEST_MSSQL_PORT"); p != "" {
		var err error
		port, err = strconv.Atoi(p)
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg := Config{
		Host: host, Port: port, User: user, Password: pass,
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

	// 服务器层收据必须存在。
	for _, tid := range []string{"mssql.server_principals", "mssql.server_role_members", "mssql.server_permissions", "mssql.databases"} {
		found := false
		for _, rc := range b.Receipts {
			if rc.TemplateID == tid {
				found = true
				if rc.Status != "ok" && rc.Status != "partial" {
					t.Errorf("receipt %s status = %s", tid, rc.Status)
				}
				t.Logf("receipt %s: status=%s rows=%d", tid, rc.Status, rc.RowCount)
			}
		}
		if !found {
			t.Errorf("missing receipt for %s", tid)
		}
	}
	// 按库收据带 param_digest。
	dbReceipts := 0
	for _, rc := range b.Receipts {
		if rc.ParamDigest != "" {
			dbReceipts++
		}
	}
	if dbReceipts == 0 {
		t.Error("no per-database receipts with param_digest")
	}
	t.Logf("per-database receipts: %d", dbReceipts)

	kinds := map[facts.FactKind]int{}
	for _, f := range b.Facts {
		kinds[f.Kind]++
	}
	for _, k := range []facts.FactKind{facts.FactPrivilege, facts.FactRoleEdge, facts.FactIdentity} {
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
	assertFact("medaudit_login 服务器主体", func(f facts.Fact) bool {
		return f.Kind == facts.FactIdentity && f.Subject == "medaudit_login" && f.Source == "mssql.server_principals"
	})
	assertFact("medaudit_user 数据库主体", func(f facts.Fact) bool {
		return f.Kind == facts.FactIdentity && f.Subject == "medaudit_user" &&
			f.Source == "mssql.db_principals" && f.Attributes["database"] == "medaudit_testdb"
	})
	assertFact("db_datareader 成员边", func(f facts.Fact) bool {
		return f.Kind == facts.FactRoleEdge && f.Subject == "medaudit_user" &&
			len(f.PermissionPath) == 2 && f.PermissionPath[0] == "db_datareader"
	})
	assertFact("DENY 语义保留", func(f facts.Fact) bool {
		return f.Kind == facts.FactPrivilege && f.Subject == "medaudit_user" &&
			f.Attributes["state"] == "DENY"
	})
	assertFact("显式 GRANT 与 DENY 并存", func(f facts.Fact) bool {
		return f.Kind == facts.FactPrivilege && f.Subject == "medaudit_user" &&
			f.Attributes["state"] == "GRANT" && f.Attributes["permission"] == "SELECT"
	})

	if b.Execution != facts.ExecutionComplete {
		t.Errorf("execution = %s, want COMPLETE", b.Execution)
	}
}

// TestQuoteIdent 验证标识符转义不可绕出。
func TestQuoteIdent(t *testing.T) {
	if got := quoteIdent("mydb"); got != "[mydb]" {
		t.Fatalf("got %q", got)
	}
	if got := quoteIdent("a]b"); got != "[a]]b]" {
		t.Fatalf("got %q", got)
	}
	if got := quoteIdent("x; DROP TABLE t;--"); got != "[x; DROP TABLE t;--]" {
		t.Fatalf("got %q", got)
	}
}
