package platform

import "testing"

func TestOpLogChain(t *testing.T) {
	db := tokenTestDB(t)
	for _, p := range []string{"/api/v1/baselines", "/api/v1/rules/x/toggle", "/api/v1/admin/wipe"} {
		if err := AppendOpLog(db, OpEntry{Actor: "admin", Method: "POST", Path: p, Status: 200, ClientIP: "10.0.0.1"}); err != nil {
			t.Fatal(err)
		}
	}
	if ok, n, _, err := VerifyOpLog(db); err != nil || !ok || n != 3 {
		t.Fatalf("verify = %v %d %v", ok, n, err)
	}
	list, total, err := ListOpLog(db, 0, 10)
	if err != nil || total != 3 || list[0].Path != "/api/v1/admin/wipe" {
		t.Fatalf("list = %+v total=%d err=%v", list, total, err)
	}

	// 篡改中间一行 → 断链定位到该行
	if _, err := db.Exec(`UPDATE op_log SET actor = 'someone' WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	if ok, _, at, _ := VerifyOpLog(db); ok || at != 2 {
		t.Fatalf("篡改后应在 id=2 断链, ok=%v at=%d", ok, at)
	}

	// 一键清场不清操作日志
	db.Exec(`UPDATE op_log SET actor = 'admin' WHERE id = 2`)
	if _, err := WipeAllData(db); err != nil {
		t.Fatal(err)
	}
	if _, total, _ := ListOpLog(db, 0, 10); total != 3 {
		t.Fatalf("清场后操作日志应保留, total=%d", total)
	}
}
