package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"

	"medaudit/internal/platform"
)

// M20 用户管理（全部经 authMiddleware 要求登录会话）：
//
//	GET  /api/v1/users                       列表（不含哈希）
//	POST /api/v1/users                       建号（must_change_pwd=1）
//	PUT  /api/v1/users/{name}/password       管理员重置（吊销该用户会话）
//	PUT  /api/v1/users/{name}/disabled       禁用/启用（禁用即吊销会话）
//
// 防自锁：禁止禁用自己、禁止禁用最后一个可用账号。
// 留痕：建号/重置/启停写服务端日志行 [user-admin]。
func registerUserRoutes(mux *http.ServeMux, db *sql.DB, sessions *platform.SessionStore) {
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		actor := currentUser(r, sessions)
		switch r.Method {
		case http.MethodGet:
			users, err := platform.ListUsers(db)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, users)
		case http.MethodPost:
			var req struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "请求解析失败", http.StatusBadRequest)
				return
			}
			if err := platform.CreateUser(db, strings.TrimSpace(req.Username), req.Password); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			log.Printf("[user-admin] %s 创建用户 %s", actor, req.Username)
			writeJSON(w, map[string]string{"status": "ok", "username": req.Username})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/v1/users/", func(w http.ResponseWriter, r *http.Request) {
		actor := currentUser(r, sessions)
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
		parts := strings.Split(rest, "/")
		if len(parts) != 2 || r.Method != http.MethodPut {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		name, err := url.PathUnescape(parts[0])
		if err != nil || name == "" {
			http.Error(w, "用户名不合法", http.StatusBadRequest)
			return
		}
		if _, _, ok := platform.UserFlags(db, name); !ok {
			http.Error(w, "用户不存在", http.StatusNotFound)
			return
		}
		switch parts[1] {
		case "password":
			var req struct {
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "请求解析失败", http.StatusBadRequest)
				return
			}
			if err := platform.AdminResetPassword(db, name, req.Password); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			sessions.DeleteUser(name)
			log.Printf("[user-admin] %s 重置用户 %s 的口令（会话已吊销）", actor, name)
			writeJSON(w, map[string]string{"status": "ok"})
		case "disabled":
			var req struct {
				Disabled bool `json:"disabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "请求解析失败", http.StatusBadRequest)
				return
			}
			if req.Disabled {
				if name == actor {
					http.Error(w, "不能禁用自己", http.StatusBadRequest)
					return
				}
				enabled, err := platform.CountEnabledUsers(db)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				if enabled <= 1 {
					http.Error(w, "不能禁用最后一个可用账号", http.StatusBadRequest)
					return
				}
			}
			if err := platform.SetUserDisabled(db, name, req.Disabled); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if req.Disabled {
				sessions.DeleteUser(name)
			}
			log.Printf("[user-admin] %s 设置用户 %s disabled=%v", actor, name, req.Disabled)
			writeJSON(w, map[string]string{"status": "ok"})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})
}
