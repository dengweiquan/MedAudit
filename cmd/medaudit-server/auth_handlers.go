package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"medaudit/internal/platform"
)

const sessionCookieName = "medaudit_session"

// loginGuard 登录失败限速：同一 (IP, 用户) 10 分钟内失败 10 次 → 冷却 5 分钟。
type loginGuard struct {
	mu       sync.Mutex
	failures map[string][]time.Time
	blocked  map[string]time.Time
}

func newLoginGuard() *loginGuard {
	return &loginGuard{failures: map[string][]time.Time{}, blocked: map[string]time.Time{}}
}

func (g *loginGuard) key(r *http.Request, user string) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	return ip + "|" + user
}

func (g *loginGuard) allow(r *http.Request, user string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	until, ok := g.blocked[g.key(r, user)]
	return !ok || time.Now().After(until)
}

func (g *loginGuard) fail(r *http.Request, user string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	k := g.key(r, user)
	now := time.Now()
	var recent []time.Time
	for _, t := range g.failures[k] {
		if now.Sub(t) < 10*time.Minute {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	g.failures[k] = recent
	if len(recent) >= 10 {
		g.blocked[k] = now.Add(5 * time.Minute)
	}
}

func (g *loginGuard) success(r *http.Request, user string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.failures, g.key(r, user))
	delete(g.blocked, g.key(r, user))
}

// registerAuthRoutes 登录/注销/当前用户/改密。
func registerAuthRoutes(mux *http.ServeMux, db *sql.DB, sessions *platform.SessionStore) {
	guard := newLoginGuard()

	mux.HandleFunc("/api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Token    string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "请求解析失败", http.StatusBadRequest)
			return
		}
		// M32：令牌登录与口令登录二选一；令牌等同 admin，失败同走限速。
		if req.Token != "" {
			if !guard.allow(r, "__token") {
				http.Error(w, "尝试过于频繁，请 5 分钟后再试", http.StatusTooManyRequests)
				return
			}
			opNote(r, "", "令牌登录")
			if !platform.AuthenticateSuperToken(db, req.Token) {
				guard.fail(r, "__token")
				http.Error(w, "令牌无效", http.StatusUnauthorized)
				return
			}
			guard.success(r, "__token")
			opNote(r, platform.DefaultAdminUser, "")
			tok := sessions.Create(platform.DefaultAdminUser)
			http.SetCookie(w, &http.Cookie{
				Name: sessionCookieName, Value: tok, Path: "/",
				HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 12 * 3600,
			})
			writeJSON(w, map[string]string{"username": platform.DefaultAdminUser})
			return
		}
		opNote(r, req.Username, "口令登录")
		if !guard.allow(r, req.Username) {
			http.Error(w, "尝试过于频繁，请 5 分钟后再试", http.StatusTooManyRequests)
			return
		}
		if !platform.AuthenticateUser(db, req.Username, req.Password) {
			guard.fail(r, req.Username)
			http.Error(w, "用户名或口令错误", http.StatusUnauthorized)
			return
		}
		guard.success(r, req.Username)
		tok := sessions.Create(req.Username)
		http.SetCookie(w, &http.Cookie{
			Name: sessionCookieName, Value: tok, Path: "/",
			HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 12 * 3600,
		})
		writeJSON(w, map[string]string{"username": req.Username})
	})

	// M32：超级令牌铸造/停用（需登录会话；Web 只接受令牌登录，不提供铸造入口）。
	mux.HandleFunc("/api/v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		actor := currentUser(r, sessions)
		if actor == "" {
			http.Error(w, "未登录", http.StatusUnauthorized)
			return
		}
		tok, err := platform.GenerateSuperToken(db, sessions)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("[token-admin] %s 生成/轮换超级令牌（admin 会话已吊销）", actor)
		writeJSON(w, map[string]string{"token": tok})
	})

	mux.HandleFunc("/api/v1/auth/token/disable", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		actor := currentUser(r, sessions)
		if actor == "" {
			http.Error(w, "未登录", http.StatusUnauthorized)
			return
		}
		if err := platform.DisableSuperToken(db, sessions); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("[token-admin] %s 停用超级令牌（admin 会话已吊销）", actor)
		writeJSON(w, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if c, err := r.Cookie(sessionCookieName); err == nil {
			sessions.Delete(c.Value)
		}
		http.SetCookie(w, &http.Cookie{
			Name: sessionCookieName, Value: "", Path: "/", HttpOnly: true, MaxAge: -1,
		})
		writeJSON(w, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/v1/auth/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		user := currentUser(r, sessions)
		if user == "" {
			http.Error(w, "未登录", http.StatusUnauthorized)
			return
		}
		_, mustChange, _ := platform.UserFlags(db, user)
		writeJSON(w, map[string]any{"username": user, "must_change_pwd": mustChange})
	})

	mux.HandleFunc("/api/v1/auth/change-password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		user := currentUser(r, sessions)
		if user == "" {
			http.Error(w, "未登录", http.StatusUnauthorized)
			return
		}
		var req struct {
			OldPassword string `json:"old_password"`
			NewPassword string `json:"new_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "请求解析失败", http.StatusBadRequest)
			return
		}
		if err := platform.ChangePassword(db, user, req.OldPassword, req.NewPassword); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	})
}

func currentUser(r *http.Request, sessions *platform.SessionStore) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	user, _ := sessions.Lookup(c.Value)
	return user
}

// authMiddleware 统一拦截 /api/v1/*：
// 放行静态资源、健康检查、登录接口、采集器下载（自有令牌），
// 以及机器通道（目标机采集器回传：POST /bundles、POST /api-audits，无浏览器会话）。
// 其余 API 需有效会话，否则 401。
func authMiddleware(next http.Handler, sessions *platform.SessionStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if !strings.HasPrefix(p, "/api/v1/") ||
			p == "/api/v1/health" ||
			p == "/api/v1/auth/login" ||
			p == "/api/v1/agent/download" ||
			(r.Method == http.MethodPost && (p == "/api/v1/bundles" || p == "/api/v1/api-audits")) {
			next.ServeHTTP(w, r)
			return
		}
		if currentUser(r, sessions) == "" {
			http.Error(w, "未登录", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
