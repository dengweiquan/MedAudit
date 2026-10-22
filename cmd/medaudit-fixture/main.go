// medaudit-fixture: M4-1 越权检测的自研夹具业务系统。
// 内置已知对/错用例：水平越权（坏）、垂直越权（坏）、正确的管理员校验（好）、
// 公开端点（好）。仅用于隔离测试环境，令牌为夹具专用固定值，无真实数据。
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type user struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
	Note  string `json:"note"`
}

var users = map[string]user{
	"1": {ID: "1", Name: "Admin", Email: "admin@example.com", Role: "admin", Note: "admin-private-note"},
	"2": {ID: "2", Name: "Alice", Email: "alice@example.com", Role: "user", Note: "alice-private-note"},
	"3": {ID: "3", Name: "Bob", Email: "bob@example.com", Role: "user", Note: "bob-private-note"},
}

// 夹具专用令牌（测试环境固定值，非真实凭据）。
var tokens = map[string]string{
	"Bearer fixture-admin-token": "1",
	"Bearer fixture-alice-token": "2",
	"Bearer fixture-bob-token":   "3",
}

func authUser(r *http.Request) (user, bool) {
	uid, ok := tokens[r.Header.Get("Authorization")]
	if !ok {
		return user{}, false
	}
	return users[uid], true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	mux := http.NewServeMux()

	// 公开端点（好用例）：匿名可达。
	mux.HandleFunc("/api/public/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})

	// 水平越权（坏用例）：只验登录，不验归属——任意登录用户可读他人资料。
	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := authUser(r); !ok {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/users/")
		if strings.Contains(id, "/") { // /api/users/{id}/note 等子路径不在此处理
			http.NotFound(w, r)
			return
		}
		u, ok := users[id]
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, 200, u) // BUG（故意的）：未校验 id == 当前用户
	})

	// 垂直越权（坏用例）：管理员列表只验登录，不验角色。
	mux.HandleFunc("/api/admin/users", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := authUser(r); !ok {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		var list []user
		for _, u := range users {
			list = append(list, u)
		}
		writeJSON(w, 200, list) // BUG（故意的）：未校验 admin 角色
	})

	// 正确实现（好用例）：管理员统计，角色校验完备。
	mux.HandleFunc("/api/admin/stats", func(w http.ResponseWriter, r *http.Request) {
		u, ok := authUser(r)
		if !ok {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		if u.Role != "admin" {
			writeJSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}
		writeJSON(w, 200, map[string]int{"user_count": len(users)})
	})

	// 本人资料（好用例）：从令牌推导身份，不接受路径参数。
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
		u, ok := authUser(r)
		if !ok {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		writeJSON(w, 200, u)
	})

	// 写端点：引擎默认只读策略应跳过（NOT_RUN）。
	mux.HandleFunc("/api/notes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, ok := authUser(r); !ok {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		writeJSON(w, 201, map[string]string{"status": "created"})
	})

	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, openAPISpec)
	})

	addr := "127.0.0.1:19090"
	fmt.Println("medaudit-fixture listening on", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Println("fixture stopped:", err)
	}
}

const openAPISpec = `{
  "openapi": "3.0.3",
  "info": {"title": "medaudit-fixture", "version": "1.0.0"},
  "paths": {
    "/api/public/health": {"get": {"summary": "公开健康检查"}},
    "/api/users/{user_id}": {"get": {"summary": "按 ID 读用户资料",
      "parameters": [{"name": "user_id", "in": "path", "required": true, "schema": {"type": "string"}}]}},
    "/api/admin/users": {"get": {"summary": "管理员用户列表"}},
    "/api/admin/stats": {"get": {"summary": "管理员统计"}},
    "/api/profile": {"get": {"summary": "本人资料"}},
    "/api/notes": {"post": {"summary": "新建备注（写操作）"}}
  }
}`
