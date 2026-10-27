package main

import (
	"database/sql"
	"net/http"
	"time"

	"medaudit/internal/platform"
)

// registerSummaryRoutes M8-4 医院级汇总 API。
func registerSummaryRoutes(mux *http.ServeMux, db *sql.DB) {
	// GET /api/v1/audit/due：各对象复检到期状态（周期 MEDAUDIT_AUDIT_CYCLE_DAYS，默认 30 天）。
	mux.HandleFunc("/api/v1/audit/due", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		days := platform.AuditCycleDays()
		items, err := platform.ListAuditDue(db, days, time.Now().UTC())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"cycle_days": days, "items": items})
	})
	mux.HandleFunc("/api/v1/summary/hospitals", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		list, err := platform.HospitalSummaries(db)
		if err != nil {
			http.Error(w, "查询失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, list)
	})
}
