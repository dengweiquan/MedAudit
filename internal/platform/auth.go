package platform

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// M12 登录鉴权：工作台用户 + 内存会话。
// 口令只存 bcrypt 哈希；默认管理员在用户表为空时首次播种，口令为产品默认
// （由交付方指定），应在首次登录后立即通过改密接口修改。

const DefaultAdminUser = "admin"
const DefaultAdminPassword = "admin@123"

// SeedDefaultAdmin 用户表为空时播种默认管理员；已有用户则不做任何事。
func SeedDefaultAdmin(db *sql.DB) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*)  FROM auth_users`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(DefaultAdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO auth_users (username, password_hash, must_change_pwd) VALUES (?, ?, 1)`,
		DefaultAdminUser, string(hash))
	return err
}

// dummyHash 用户不存在时也执行一次 bcrypt 比较，抹平明显的时序差异。
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("medaudit-dummy"), bcrypt.DefaultCost)

// AuthenticateUser 校验用户名/口令；disabled 账号（M20）一律拒绝。
func AuthenticateUser(db *sql.DB, username, password string) bool {
	var hash string
	var disabled int
	err := db.QueryRow(`SELECT password_hash, disabled FROM auth_users WHERE username = ?`, username).Scan(&hash, &disabled)
	if err == sql.ErrNoRows {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return false
	}
	if err != nil {
		return false
	}
	ok := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	if disabled != 0 {
		return false
	}
	return ok
}

// ChangePassword 校验旧口令后更新哈希；新口令至少 8 位。
func ChangePassword(db *sql.DB, username, oldPassword, newPassword string) error {
	if len(newPassword) < 8 {
		return fmt.Errorf("新口令至少 8 位")
	}
	if !AuthenticateUser(db, username, oldPassword) {
		return fmt.Errorf("当前口令不正确")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE auth_users SET password_hash = ?, must_change_pwd = 0, updated_at = CURRENT_TIMESTAMP WHERE username = ?`,
		string(hash), username)
	return err
}

// ---------- 会话（进程内存，重启需重新登录） ----------

type sessionEntry struct {
	username string
	exp      time.Time
}

type SessionStore struct {
	mu  sync.Mutex
	m   map[string]sessionEntry
	ttl time.Duration
}

func NewSessionStore() *SessionStore {
	return &SessionStore{m: make(map[string]sessionEntry), ttl: 12 * time.Hour}
}

func (s *SessionStore) Create(username string) string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	tok := hex.EncodeToString(b[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, e := range s.m {
		if now.After(e.exp) {
			delete(s.m, k)
		}
	}
	s.m[tok] = sessionEntry{username: username, exp: now.Add(s.ttl)}
	return tok
}

func (s *SessionStore) Lookup(tok string) (string, bool) {
	if tok == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[tok]
	if !ok || time.Now().After(e.exp) {
		delete(s.m, tok)
		return "", false
	}
	return e.username, true
}

func (s *SessionStore) Delete(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, tok)
}

// DeleteUser 吊销某用户的全部会话（M20 禁用/重置口令时调用）。
func (s *SessionStore) DeleteUser(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for tok, e := range s.m {
		if e.username == username {
			delete(s.m, tok)
		}
	}
}

// Clear 吊销全部会话（一键清场时调用，M27）。
func (s *SessionStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = make(map[string]sessionEntry)
}

// ---------- M20 用户管理 ----------

// UserInfo 用户列表行（不含口令哈希）。
type UserInfo struct {
	Username      string `json:"username"`
	Disabled      bool   `json:"disabled"`
	MustChangePwd bool   `json:"must_change_pwd"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// ListUsers 全部用户（按用户名排序）。
func ListUsers(db *sql.DB) ([]UserInfo, error) {
	rows, err := db.Query(`SELECT username, disabled, must_change_pwd, created_at, updated_at
		FROM auth_users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserInfo{}
	for rows.Next() {
		var u UserInfo
		var dis, mcp int
		if err := rows.Scan(&u.Username, &dis, &mcp, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		u.Disabled = dis != 0
		u.MustChangePwd = mcp != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

// UserFlags 读单用户标志（不存在时 ok=false）。
func UserFlags(db *sql.DB, username string) (disabled, mustChange, ok bool) {
	var dis, mcp int
	err := db.QueryRow(`SELECT disabled, must_change_pwd FROM auth_users WHERE username = ?`,
		username).Scan(&dis, &mcp)
	if err != nil {
		return false, false, false
	}
	return dis != 0, mcp != 0, true
}

// CountEnabledUsers 未禁用账号数（防自锁判定）。
func CountEnabledUsers(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM auth_users WHERE disabled = 0`).Scan(&n)
	return n, err
}

func validUsername(u string) bool {
	if u == "" || len(u) > 64 {
		return false
	}
	for _, c := range u {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// CreateUser 建号：用户名唯一、口令至少 8 位、新号强制首登改密。
func CreateUser(db *sql.DB, username, password string) error {
	if !validUsername(username) {
		return fmt.Errorf("用户名不合法（1–64 字符，仅字母/数字/_/-/.）")
	}
	if len(password) < 8 {
		return fmt.Errorf("口令至少 8 位")
	}
	if _, _, ok := UserFlags(db, username); ok {
		return fmt.Errorf("用户名 %s 已存在", username)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO auth_users (username, password_hash, must_change_pwd) VALUES (?, ?, 1)`,
		username, string(hash))
	return err
}

// AdminResetPassword 管理员重置口令：置 must_change_pwd=1（会话吊销由调用方处理）。
func AdminResetPassword(db *sql.DB, username, newPassword string) error {
	if len(newPassword) < 8 {
		return fmt.Errorf("口令至少 8 位")
	}
	if _, _, ok := UserFlags(db, username); !ok {
		return fmt.Errorf("用户 %s 不存在", username)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE auth_users SET password_hash = ?, must_change_pwd = 1, updated_at = CURRENT_TIMESTAMP WHERE username = ?`,
		string(hash), username)
	return err
}

// SetUserDisabled 禁用/启用账号。
func SetUserDisabled(db *sql.DB, username string, disabled bool) error {
	v := 0
	if disabled {
		v = 1
	}
	res, err := db.Exec(`UPDATE auth_users SET disabled = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`,
		v, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("用户 %s 不存在", username)
	}
	return nil
}
