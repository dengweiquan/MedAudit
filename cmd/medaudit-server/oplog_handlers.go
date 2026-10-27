package main

import (
	"context"
	"database/sql"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"medaudit/internal/platform"
)

// 平台操作日志：写操作（非 GET/HEAD/OPTIONS）与文件下载（证据、报告、备份）
// 一律落 op_log，带操作人、来源 IP、结果状态码；不记录请求体（避免口令入库）。

type opLogKey struct{}

// opNote 供处理函数补充操作人或备注（如登录：请求前尚无会话）。
func opNote(r *http.Request, actor, note string) {
	if e, ok := r.Context().Value(opLogKey{}).(*platform.OpEntry); ok {
		if actor != "" {
			e.Actor = actor
		}
		if note != "" {
			e.Note = note
		}
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func opLogMiddleware(next http.Handler, db *sql.DB, sessions *platform.SessionStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
			next.ServeHTTP(w, r)
			return
		}
		e := &platform.OpEntry{
			Actor: currentUser(r, sessions), Method: r.Method,
			Path: r.URL.Path, ClientIP: clientIP(r),
		}
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), opLogKey{}, e)))

		write := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
		download := strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment")
		if !write && !download {
			return
		}
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		e.Status = rec.status
		if e.Actor == "" {
			e.Actor = "-"
		}
		if err := platform.AppendOpLog(db, *e); err != nil {
			log.Printf("[op-log] 写入失败: %v (%s %s %s)", err, e.Actor, e.Method, e.Path)
		}
	})
}

// registerOpLogRoutes GET /api/v1/admin/oplog?offset=&limit= 列表；
// GET /api/v1/admin/oplog/verify 复核哈希链。
func registerOpLogRoutes(mux *http.ServeMux, db *sql.DB) {
	mux.HandleFunc("/api/v1/admin/oplog", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		items, total, err := platform.ListOpLog(db, offset, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"total": total, "items": items})
	})
	mux.HandleFunc("/api/v1/admin/oplog/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ok, n, brokenAt, err := platform.VerifyOpLog(db)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"ok": ok, "rows": n, "broken_at": brokenAt})
	})
}
