package main

import (
	"database/sql"
	"net/http"

	"medaudit/internal/platform"
)

// registerSummaryRoutes M8-4 医院级汇总 API。
func registerSummaryRoutes(mux *http.ServeMux, db *sql.DB) {
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
