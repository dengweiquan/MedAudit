package platform

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// M32 超级令牌：部署级第二种登录凭证，等同 admin 权限。
// 原文只在生成时返回一次；库里只存 bcrypt 哈希。未生成前令牌登录一律失败。
// 令牌铸造与用户管理同口径（M20 无 RBAC 设计）：只要求登录会话。
// M37-3.2：令牌带有效期（缺省 90 天，最长 365 天），过期拒绝并提示重新生成；
// 可选来源限制 MEDAUDIT_TOKEN_ALLOW_CIDR（逗号分隔网段或单个 IP，未设则不限）。

const superTokenName = "super"

const (
	defaultTokenDays = 90
	maxTokenDays     = 365
	// tokenTimeFormat 与 SQLite CURRENT_TIMESTAMP 文本格式一致（UTC）。
	tokenTimeFormat = "2006-01-02 15:04:05"
)

// GenerateSuperToken 生成/轮换超级令牌，返回原文（调用方只展示一次）。
// days <= 0 时取缺省 90 天；超过 365 天报错。轮换即吊销 admin 全部会话
// （与管理员重置口令同口径）。
func GenerateSuperToken(db *sql.DB, sessions *SessionStore, days int) (string, error) {
	if days <= 0 {
		days = defaultTokenDays
	}
	if days > maxTokenDays {
		return "", fmt.Errorf("令牌有效期最长 %d 天", maxTokenDays)
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	raw := hex.EncodeToString(b[:])
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	expires := time.Now().UTC().AddDate(0, 0, days).Format(tokenTimeFormat)
	if _, err := db.Exec(`INSERT INTO auth_tokens (name, token_hash, disabled, expires_at, updated_at)
		VALUES (?, ?, 0, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(name) DO UPDATE SET token_hash = excluded.token_hash, disabled = 0, expires_at = excluded.expires_at, updated_at = CURRENT_TIMESTAMP`,
		superTokenName, string(hash), expires); err != nil {
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

// AuthenticateSuperToken 校验令牌：行不存在、已停用、admin 被禁用均拒绝；
// 过期时 ok=false 且 expired=true（调用方提示重新生成）。
// 行不存在时同样执行一次 bcrypt 比较，抹平明显的时序差异。
func AuthenticateSuperToken(db *sql.DB, token string) (ok, expired bool) {
	var hash string
	var disabled int
	var expiresAt sql.NullString
	err := db.QueryRow(`SELECT token_hash, disabled, expires_at FROM auth_tokens WHERE name = ?`, superTokenName).Scan(&hash, &disabled, &expiresAt)
	if err == sql.ErrNoRows {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(token))
		return false, false
	}
	if err != nil || disabled != 0 {
		return false, false
	}
	var adminDisabled int
	if err := db.QueryRow(`SELECT disabled FROM auth_users WHERE username = ?`, DefaultAdminUser).Scan(&adminDisabled); err != nil || adminDisabled != 0 {
		return false, false
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(token)) != nil {
		return false, false
	}
	if expiresAt.Valid && expiresAt.String != "" {
		if exp, err := time.Parse(tokenTimeFormat, expiresAt.String); err == nil && time.Now().UTC().After(exp) {
			return false, true
		}
	}
	return true, false
}

// TokenSourceAllowed 判断令牌登录的来源 IP 是否在 MEDAUDIT_TOKEN_ALLOW_CIDR
// 允许范围内。未配置时不限；配置了但无一网段可解析时拒绝全部（fail closed）。
// 条目可为 CIDR（如 10.0.0.0/8）或单个 IP（视为 /32 或 /128）。
func TokenSourceAllowed(ip string) bool {
	raw := strings.TrimSpace(os.Getenv("MEDAUDIT_TOKEN_ALLOW_CIDR"))
	if raw == "" {
		return true
	}
	addr := net.ParseIP(strings.TrimSpace(ip))
	if addr == nil {
		return false
	}
	var nets []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(part); err == nil {
			nets = append(nets, n)
			continue
		}
		if single := net.ParseIP(part); single != nil {
			bits := 128
			if single.To4() != nil {
				bits = 32
			}
			if _, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", single.String(), bits)); err == nil {
				nets = append(nets, n)
			}
		}
	}
	if len(nets) == 0 {
		return false
	}
	for _, n := range nets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}
