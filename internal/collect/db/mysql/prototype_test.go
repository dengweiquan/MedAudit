package mysql

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"medaudit/internal/facts"
)

// TestPrototypeLive 针对 M0 测试 MySQL 实例的真实连接原型。
// 需要环境变量：MEDAUDIT_TEST_MYSQL_HOST/PORT/USER/PASS，未设置则跳过。
func TestPrototypeLive(t *testing.T) {
	host := os.Getenv("MEDAUDIT_TEST_MYSQL_HOST")
	user := os.Getenv("MEDAUDIT_TEST_MYSQL_USER")
	pass := os.Getenv("MEDAUDIT_TEST_MYSQL_PASS")
	if host == "" || user == "" {
		t.Skip("MEDAUDIT_TEST_MYSQL_* 未设置，跳过真实连接原型")
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
		ConnectTimeout: 10 * time.Second, QueryTimeout: 10 * time.Second,
	}
	ctx := context.Background()
	db, err := Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer db.Close()

	b, err := PrototypeCollect(ctx, db, cfg, "0.1.0-m0")
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if errs := b.Validate(); len(errs) != 0 {
		t.Fatalf("bundle validate: %v", errs)
	}
	if b.Execution != facts.ExecutionComplete {
		t.Fatalf("execution = %s", b.Execution)
	}
	if len(b.Facts) == 0 || len(b.Receipts) == 0 {
		t.Fatal("facts/receipts 为空")
	}
	t.Logf("MySQL 版本: %s, 收据: %s/%s",
		b.Facts[0].Attributes["version"], b.Receipts[0].TemplateID, b.Receipts[0].Status)
}
