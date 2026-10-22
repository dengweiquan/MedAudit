package oracle

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"medaudit/internal/facts"
)

// TestPrototypeLive 针对 M0 测试 Oracle 实例的真实连接原型。
// 需要环境变量：MEDAUDIT_TEST_ORA_HOST/PORT/SERVICE/USER/PASS，未设置则跳过。
// 驱动为纯 Go（go-ora），无 CGO / Instant Client 依赖。
func TestPrototypeLive(t *testing.T) {
	host := os.Getenv("MEDAUDIT_TEST_ORA_HOST")
	user := os.Getenv("MEDAUDIT_TEST_ORA_USER")
	pass := os.Getenv("MEDAUDIT_TEST_ORA_PASS")
	svc := os.Getenv("MEDAUDIT_TEST_ORA_SERVICE")
	if host == "" || user == "" || svc == "" {
		t.Skip("MEDAUDIT_TEST_ORA_* 未设置，跳过真实连接原型")
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
		ConnectTimeout: 15 * time.Second, QueryTimeout: 15 * time.Second,
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
	t.Logf("Oracle 版本: %s, 用户: %s, 收据: %s/%s",
		b.Facts[0].Attributes["version"], b.Facts[0].Attributes["db_user"],
		b.Receipts[0].TemplateID, b.Receipts[0].Status)
}
