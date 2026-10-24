package platform

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func tokenTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "tok.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := SeedDefaultAdmin(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestSuperToken(t *testing.T) {
	db := tokenTestDB(t)
	sessions := NewSessionStore()

	// 未生成前一律失败
	if AuthenticateSuperToken(db, "anything") {
		t.Fatal("未生成令牌却验证通过")
	}
	// 生成并验证
	raw, err := GenerateSuperToken(db, sessions)
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" {
		t.Fatal("未返回令牌原文")
	}
	if !AuthenticateSuperToken(db, raw) {
		t.Fatal("刚生成的令牌验证失败")
	}
	if AuthenticateSuperToken(db, raw+"x") {
		t.Fatal("错误令牌验证通过")
	}
	// 库里只存哈希，不存原文
	var hash string
	if err := db.QueryRow(`SELECT token_hash FROM auth_tokens WHERE name = 'super'`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash == raw || len(hash) < 20 || hash[0] != '$' {
		t.Fatalf("库里应为 bcrypt 哈希，得到 %q", hash)
	}
	// 轮换：旧令牌失效，新令牌有效
	raw2, err := GenerateSuperToken(db, sessions)
	if err != nil {
		t.Fatal(err)
	}
	if AuthenticateSuperToken(db, raw) {
		t.Fatal("轮换后旧令牌仍有效")
	}
	if !AuthenticateSuperToken(db, raw2) {
		t.Fatal("轮换后新令牌验证失败")
	}
	// 停用：新令牌失效；口令登录不受影响
	if err := DisableSuperToken(db, sessions); err != nil {
		t.Fatal(err)
	}
	if AuthenticateSuperToken(db, raw2) {
		t.Fatal("停用后令牌仍有效")
	}
	if !AuthenticateUser(db, DefaultAdminUser, DefaultAdminPassword) {
		t.Fatal("停用令牌后口令登录受影响")
	}
	// 未生成时停用应报错
	db2 := tokenTestDB(t)
	if err := DisableSuperToken(db2, sessions); err == nil {
		t.Fatal("未生成令牌停用应报错")
	}
}
