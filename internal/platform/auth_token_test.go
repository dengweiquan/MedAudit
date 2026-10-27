package platform

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
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

func authOK(t *testing.T, db *sql.DB, token string) bool {
	t.Helper()
	ok, _ := AuthenticateSuperToken(db, token)
	return ok
}

func TestSuperToken(t *testing.T) {
	db := tokenTestDB(t)
	sessions := NewSessionStore()

	// 未生成前一律失败
	if authOK(t, db, "anything") {
		t.Fatal("未生成令牌却验证通过")
	}
	// 生成并验证
	raw, err := GenerateSuperToken(db, sessions, 0)
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" {
		t.Fatal("未返回令牌原文")
	}
	if !authOK(t, db, raw) {
		t.Fatal("刚生成的令牌验证失败")
	}
	if authOK(t, db, raw+"x") {
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
	raw2, err := GenerateSuperToken(db, sessions, 0)
	if err != nil {
		t.Fatal(err)
	}
	if authOK(t, db, raw) {
		t.Fatal("轮换后旧令牌仍有效")
	}
	if !authOK(t, db, raw2) {
		t.Fatal("轮换后新令牌验证失败")
	}
	// 停用：新令牌失效；口令登录不受影响
	if err := DisableSuperToken(db, sessions); err != nil {
		t.Fatal(err)
	}
	if authOK(t, db, raw2) {
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

// M37-3.2：有效期缺省 90 天、最长 365 天；过期拒绝并区分过期与无效。
func TestGenerateSuperTokenExpiry(t *testing.T) {
	db := tokenTestDB(t)
	sessions := NewSessionStore()
	expiry := func() time.Time {
		t.Helper()
		var s string
		if err := db.QueryRow(`SELECT expires_at FROM auth_tokens WHERE name = 'super'`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		exp, err := time.Parse(tokenTimeFormat, s)
		if err != nil {
			t.Fatalf("expires_at 解析失败 %q: %v", s, err)
		}
		return exp
	}
	within := func(got time.Time, days int) bool {
		d := time.Until(got)
		return d > time.Duration(days-1)*24*time.Hour && d < time.Duration(days+1)*24*time.Hour
	}

	// 缺省（days<=0）= 90 天
	if _, err := GenerateSuperToken(db, sessions, 0); err != nil {
		t.Fatal(err)
	}
	if !within(expiry(), 90) {
		t.Errorf("缺省有效期应约 90 天，实际 expires_at 距今 %v", time.Until(expiry()))
	}
	if _, err := GenerateSuperToken(db, sessions, -5); err != nil {
		t.Fatal(err)
	}
	if !within(expiry(), 90) {
		t.Errorf("负天数应回落缺省 90 天，实际 expires_at 距今 %v", time.Until(expiry()))
	}
	// 365 天通过，366 天拒绝
	if _, err := GenerateSuperToken(db, sessions, 365); err != nil {
		t.Fatal(err)
	}
	if !within(expiry(), 365) {
		t.Errorf("365 天有效期异常，实际 expires_at 距今 %v", time.Until(expiry()))
	}
	if _, err := GenerateSuperToken(db, sessions, 366); err == nil {
		t.Fatal("366 天应报错")
	}
}

func TestAuthenticateSuperTokenExpired(t *testing.T) {
	db := tokenTestDB(t)
	sessions := NewSessionStore()
	raw, err := GenerateSuperToken(db, sessions, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !authOK(t, db, raw) {
		t.Fatal("未过期令牌应有效")
	}
	// 把到期时间改到过去：应拒绝且 expired=true；错令牌仍只是无效。
	if _, err := db.Exec(`UPDATE auth_tokens SET expires_at = '2000-01-01 00:00:00' WHERE name = 'super'`); err != nil {
		t.Fatal(err)
	}
	ok, expired := AuthenticateSuperToken(db, raw)
	if ok || !expired {
		t.Fatalf("过期令牌应 ok=false expired=true，实际 ok=%v expired=%v", ok, expired)
	}
	ok, expired = AuthenticateSuperToken(db, raw+"x")
	if ok || expired {
		t.Fatalf("错令牌应 ok=false expired=false，实际 ok=%v expired=%v", ok, expired)
	}
	// 迁移 014 的老令牌回填：生成时间 + 90 天（以 created_at 为准）。
	if _, err := db.Exec(`UPDATE auth_tokens SET expires_at = datetime(created_at, '+90 days') WHERE name = 'super'`); err != nil {
		t.Fatal(err)
	}
	if !authOK(t, db, raw) {
		t.Fatal("回填 90 天后的令牌应恢复有效")
	}
}

func TestTokenSourceAllowed(t *testing.T) {
	t.Setenv("MEDAUDIT_TOKEN_ALLOW_CIDR", "")
	if !TokenSourceAllowed("8.8.8.8") {
		t.Fatal("未配置时应不限来源")
	}
	t.Setenv("MEDAUDIT_TOKEN_ALLOW_CIDR", "10.0.0.0/8, 192.168.1.5")
	if !TokenSourceAllowed("10.1.2.3") {
		t.Fatal("10.0.0.0/8 内应放行")
	}
	if !TokenSourceAllowed("192.168.1.5") {
		t.Fatal("单个 IP 条目应放行")
	}
	if TokenSourceAllowed("8.8.8.8") {
		t.Fatal("范围外应拒绝")
	}
	if TokenSourceAllowed("not-an-ip") {
		t.Fatal("非法 IP 应拒绝")
	}
	// 配置了但无一可解析：fail closed。
	t.Setenv("MEDAUDIT_TOKEN_ALLOW_CIDR", "garbage!!!")
	if TokenSourceAllowed("10.1.2.3") {
		t.Fatal("无有效网段时应拒绝全部")
	}
}
