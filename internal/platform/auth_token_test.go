package platform

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
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

// M37-fix-1：014 回填错误由 015 修正；expires_at 无法解析按过期拒绝；网段部分非法拒绝全部。
func oldTokenDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "oldtok.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT NOT NULL PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatal(err)
	}
	// 只应用到 010（含 auth_tokens，但无 expires_at 列），模拟 3.2 之前的老库。
	entries, err := sqliteMigrations.ReadDir("sqlite_migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if name > "010_auth_tokens.sql" {
			continue
		}
		body, err := sqliteMigrations.ReadFile("sqlite_migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			t.Fatalf("应用老迁移 %s 失败: %v", name, err)
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO schema_migrations (version) VALUES (?)`,
			name[:len(name)-len(".sql")]); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestMigration015FixesOldTokenBackfill(t *testing.T) {
	db := oldTokenDB(t)
	if err := SeedDefaultAdmin(db); err != nil {
		t.Fatal(err)
	}
	// 旧令牌：1 月生成、之后轮换过（created_at ≠ updated_at），哈希对应已知原文。
	raw := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	updated := time.Now().UTC().Format(tokenTimeFormat)
	if _, err := db.Exec(`INSERT INTO auth_tokens (name, token_hash, disabled, created_at, updated_at)
		VALUES ('super', ?, 0, '2026-01-01 00:00:00', ?)`, string(hash), updated); err != nil {
		t.Fatal(err)
	}
	// 真实执行 Migrate：014 先按 created_at 回填（已过期），015 再按 updated_at 重算。
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	var expires string
	if err := db.QueryRow(`SELECT expires_at FROM auth_tokens WHERE name = 'super'`).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	want, _ := time.Parse(tokenTimeFormat, updated)
	want = want.AddDate(0, 0, 90)
	if expires != want.Format(tokenTimeFormat) {
		t.Fatalf("015 应按 updated_at + 90 天重算，实际 expires_at=%q，期望 %q", expires, want.Format(tokenTimeFormat))
	}
	if ok, _ := AuthenticateSuperToken(db, raw); !ok {
		t.Fatal("015 修正后令牌应仍有效")
	}
	// 新代码按 90 天铸造的令牌：重跑 015 不应误改。
	raw2, err := GenerateSuperToken(db, NewSessionStore(), 90)
	if err != nil {
		t.Fatal(err)
	}
	var exp2 string
	if err := db.QueryRow(`SELECT expires_at FROM auth_tokens WHERE name = 'super'`).Scan(&exp2); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM schema_migrations WHERE version = '015_auth_tokens_expiry_fix'`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	var exp2b string
	if err := db.QueryRow(`SELECT expires_at FROM auth_tokens WHERE name = 'super'`).Scan(&exp2b); err != nil {
		t.Fatal(err)
	}
	if exp2 != exp2b {
		t.Fatalf("重跑 015 不应改动新代码铸造的令牌：%q -> %q", exp2, exp2b)
	}
	if ok, _ := AuthenticateSuperToken(db, raw2); !ok {
		t.Fatal("新代码令牌重跑迁移后应仍有效")
	}
}

func TestAuthenticateSuperTokenUnparseableExpiry(t *testing.T) {
	db := tokenTestDB(t)
	raw, err := GenerateSuperToken(db, NewSessionStore(), 90)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE auth_tokens SET expires_at = 'not-a-date' WHERE name = 'super'`); err != nil {
		t.Fatal(err)
	}
	ok, expired := AuthenticateSuperToken(db, raw)
	if ok || !expired {
		t.Fatalf("无法解析的 expires_at 应按过期拒绝，实际 ok=%v expired=%v", ok, expired)
	}
}

func TestTokenSourceAllowedPartialInvalid(t *testing.T) {
	t.Setenv("MEDAUDIT_TOKEN_ALLOW_CIDR", "10.0.0.0/8, garbage!!!")
	if TokenSourceAllowed("10.1.2.3") {
		t.Fatal("网段配置部分非法时，即使网段内也应拒绝全部")
	}
	bad := TokenAllowCIDRInvalid()
	if len(bad) != 1 || bad[0] != "garbage!!!" {
		t.Fatalf("非法条目应为 [garbage!!!]，实际 %v", bad)
	}
}
