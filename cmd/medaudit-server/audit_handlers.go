package main

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"medaudit/internal/platform"
	"medaudit/internal/rules"
)

// 一键审计（M6）：数据库类资产采集→导入→评估→报告；口令仅本次使用、不落库。
func registerAuditRoutes(mux *http.ServeMux, db *sql.DB, reg *rules.Registry, kr *platform.EvidenceKeyring, collectorBin string) {
	// POST /api/v1/audit/run {asset_id, password, baseline_id?, created_by?}
	// 数据库类资产一键审计：采集→导入→评估→报告；口令仅本次使用、不落库。
	mux.HandleFunc("/api/v1/audit/run", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			AssetID    string `json:"asset_id"`
			Password   string `json:"password"`
			BaselineID string `json:"baseline_id"`
			CreatedBy  string `json:"created_by"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AssetID == "" {
			http.Error(w, "asset_id 必填", http.StatusBadRequest)
			return
		}
		result, err := platform.RunDBAudit(r.Context(), db, reg, kr, collectorBin,
			req.AssetID, req.Password, req.BaselineID, req.CreatedBy)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, result)
	})
}
