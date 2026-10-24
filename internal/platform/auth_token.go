package platform

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// M32 超级令牌：部署级第二种登录凭证，等同 admin 权限。
// 原文只在生成时返回一次；库里只存 bcrypt 哈希。未生成前令牌登录一律失败。
// 令牌铸造与用户管理同口径（M20 无 RBAC 设计）：只要求登录会话。

const superTokenName = "super"

// GenerateSuperToken 生成/轮换超级令牌，返回原文（调用方只展示一次）。
// 轮换即吊销 admin 全部会话（与管理员重置口令同口径）。
func GenerateSuperToken(db *sql.DB, sessions *SessionStore) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	raw := hex.EncodeToString(b[:])
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	if _, err := db.Exec(`INSERT INTO auth_tokens (name, token_hash, disabled, updated_at)
		VALUES (?, ?, 0, CURRENT_TIMESTAMP)
		ON CONFLICT(name) DO UPDATE SET token_hash = excluded.token_hash, disabled = 0, updated_at = CURRENT_TIMESTAMP`,
		superTokenName, string(hash)); err != nil {
		return "", err
	}
	if sessions != nil {
		sessions.DeleteUser(DefaultAdminUser)
	}
	return raw, nil
}

// DisableSuperToken 停用超级令牌（之后令牌登录被拒）；同时吊销 admin 会话。
func DisableSuperToken(db *sql.DB, sessions *SessionStore) error {
	res, err := db.Exec(`UPDATE auth_tokens SET disabled = 1, updated_at = CURRENT_TIMESTAMP WHERE name = ?`, superTokenName)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("尚未生成超级令牌")
	}
	if sessions != nil {
		sessions.DeleteUser(DefaultAdminUser)
	}
	return nil
}

// AuthenticateSuperToken 校验令牌：行不存在、已停用、admin 被禁用均拒绝。
// 行不存在时同样执行一次 bcrypt 比较，抹平明显的时序差异。
func AuthenticateSuperToken(db *sql.DB, token string) bool {
	var hash string
	var disabled int
	err := db.QueryRow(`SELECT token_hash, disabled FROM auth_tokens WHERE name = ?`, superTokenName).Scan(&hash, &disabled)
	if err == sql.ErrNoRows {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(token))
		return false
	}
	if err != nil || disabled != 0 {
		return false
	}
	var adminDisabled int
	if err := db.QueryRow(`SELECT disabled FROM auth_users WHERE username = ?`, DefaultAdminUser).Scan(&adminDisabled); err != nil || adminDisabled != 0 {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(token)) == nil
}
