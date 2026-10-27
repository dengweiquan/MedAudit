package platform

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func testKeyring(t *testing.T) *EvidenceKeyring {
	t.Helper()
	kr, err := NewEvidenceKeyring(1, map[uint16][]byte{1: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func TestScheduler(t *testing.T) {
	db := tokenTestDB(t)
	kr := testKeyring(t)
	db.Exec(`INSERT INTO hospitals (id, name) VALUES ('h', 'H')`)
	db.Exec(`INSERT INTO assets (id, hospital_id, kind, name) VALUES ('db1', 'h', 'db-mysql', 'MySQL'), ('x1', 'h', 'api', 'API')`)

	if err := SaveSchedule(db, nil, "db1", 30, "pw", "", "admin"); err == nil {
		t.Fatal("无证据密钥时应拒绝开启")
	}
	if err := SaveSchedule(db, kr, "x1", 30, "pw", "", "admin"); err == nil {
		t.Fatal("不支持的类型应拒绝")
	}
	if err := SaveSchedule(db, kr, "db1", 30, "", "", "admin"); err == nil {
		t.Fatal("首次开启无口令应拒绝")
	}
	if err := SaveSchedule(db, kr, "db1", 30, "s3cret-pw", "", "admin"); err != nil {
		t.Fatal(err)
	}
	var cred []byte
	db.QueryRow(`SELECT cred FROM audit_schedules WHERE asset_id = 'db1'`).Scan(&cred)
	if bytes.Contains(cred, []byte("s3cret-pw")) {
		t.Fatal("口令不得明文落库")
	}

	s := &Scheduler{DB: db, Keyring: kr, Interval: time.Hour, running: map[string]bool{}}
	var gotPW string
	fail := false
	s.run = func(ctx context.Context, mode, assetID, password, baselineID string) (string, error) {
		gotPW = password
		if fail {
			return "", errors.New("连接被拒绝")
		}
		return "b-new", nil
	}

	// 从未审计 → 立即到期
	s.Tick(context.Background())
	if gotPW != "s3cret-pw" {
		t.Fatalf("调度器应解密出原口令, got %q", gotPW)
	}
	list, _ := ListSchedules(db)
	if len(list) != 1 || list[0].LastStatus != "ok" || list[0].LastBundleID != "b-new" {
		t.Fatalf("执行结果 = %+v", list)
	}
	next, _ := parseStoredTime(list[0].NextRunAt)
	if next.Before(utcNow().Add(29 * 24 * time.Hour)) {
		t.Fatalf("成功后下次应在一个周期后, got %s", list[0].NextRunAt)
	}

	// 未到期不执行
	gotPW = ""
	s.Tick(context.Background())
	if gotPW != "" {
		t.Fatal("未到期不应执行")
	}

	// 失败 → 记录失败、次日重试、生成复检失败告警
	fail = true
	if err := s.RunOne(context.Background(), "db1"); err == nil {
		t.Fatal("应返回失败")
	}
	list, _ = ListSchedules(db)
	if list[0].LastStatus != "failed" || list[0].LastError == "" {
		t.Fatalf("失败状态 = %+v", list[0])
	}
	alerts, _ := ListAlerts(db, true)
	if len(alerts) != 1 || alerts[0].Kind != "audit_failed" {
		t.Fatalf("应有复检失败告警: %+v", alerts)
	}
	if ok, n, _, _ := VerifyOpLog(db); !ok || n != 2 {
		t.Fatalf("两次执行应各记一条操作日志, ok=%v n=%d", ok, n)
	}

	// 关闭即删除口令
	if err := DeleteSchedule(db, "db1"); err != nil {
		t.Fatal(err)
	}
	var cnt int
	db.QueryRow(`SELECT COUNT(*) FROM audit_schedules`).Scan(&cnt)
	if cnt != 0 {
		t.Fatal("关闭后应删除保存的口令")
	}
}
