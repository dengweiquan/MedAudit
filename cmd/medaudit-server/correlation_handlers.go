package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"medaudit/internal/platform"
)

// registerCorrelationRoutes M8-1 跨层关联分析 API。
func registerCorrelationRoutes(mux *http.ServeMux, db *sql.DB) {
	mux.HandleFunc("/api/v1/correlations", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			list, err := platform.ListCorrelations(db)
			if err != nil {
				http.Error(w, "查询失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, list)
		case http.MethodPost:
			var req struct {
				BundleIDs []string `json:"bundle_ids"`
				CreatedBy string   `json:"created_by"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "请求体不是合法 JSON", http.StatusBadRequest)
				return
			}
			detail, err := platform.RunCorrelation(db, req.BundleIDs, req.CreatedBy)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, detail)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/correlations/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/correlations/")
		detail, err := platform.GetCorrelation(db, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, detail)
	})
}
