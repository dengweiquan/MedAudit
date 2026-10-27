package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"medaudit/internal/platform"
)

// registerScheduleRoutes 定期自动复检：
//   - GET    /api/v1/schedules               已开启的对象及最近执行情况（不含口令）
//   - PUT    /api/v1/schedules/{asset}       开启/修改 {cycle_days, password?, baseline_id?}
//   - DELETE /api/v1/schedules/{asset}       关闭并删除保存的口令
//   - POST   /api/v1/schedules/{asset}/run   立即执行一次（异步）
func registerScheduleRoutes(mux *http.ServeMux, db *sql.DB, kr *platform.EvidenceKeyring,
	sched *platform.Scheduler, sessions *platform.SessionStore) {
	mux.HandleFunc("/api/v1/schedules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		items, err := platform.ListSchedules(db)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"items": items, "key_ready": kr != nil})
	})
	mux.HandleFunc("/api/v1/schedules/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/schedules/")
		if strings.HasSuffix(rest, "/run") {
			id := strings.TrimSuffix(rest, "/run")
			if r.Method != http.MethodPost || id == "" || strings.Contains(id, "/") {
				http.NotFound(w, r)
				return
			}
			if err := sched.RunNow(id); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			writeJSON(w, map[string]string{"status": "started"})
			return
		}
		if rest == "" || strings.Contains(rest, "/") {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var req struct {
				CycleDays  int    `json:"cycle_days"`
				Password   string `json:"password"`
				BaselineID string `json:"baseline_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "请求解析失败", http.StatusBadRequest)
				return
			}
			if err := platform.SaveSchedule(db, kr, rest, req.CycleDays, req.Password, req.BaselineID, currentUser(r, sessions)); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]string{"status": "ok"})
		case http.MethodDelete:
			if err := platform.DeleteSchedule(db, rest); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]string{"status": "ok"})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}
