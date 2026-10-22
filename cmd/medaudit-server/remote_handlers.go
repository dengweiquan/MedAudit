package main

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"medaudit/internal/platform"
	"medaudit/internal/rules"
)

// M9 远程推送审计路由：
//   - POST /api/v1/audit/run-remote {asset_id, password, baseline_id?, created_by?}
//     OS/中间件资产：推送采集器→目标机执行→回传事实包→评估→报告；口令仅本次使用、不落库。
//   - GET /api/v1/agent/download?token=<一次性令牌>
//     Windows 目标机拉取采集器 exe；令牌单次有效、5 分钟过期（platform.TokenStore）。
func registerRemoteRoutes(mux *http.ServeMux, db *sql.DB, reg *rules.Registry, kr *platform.EvidenceKeyring,
	linuxBin, winBin string, tokens *platform.TokenStore) {

	mux.HandleFunc("/api/v1/audit/run-remote", func(w http.ResponseWriter, r *http.Request) {
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
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "请求解析失败", http.StatusBadRequest)
			return
		}
		if req.AssetID == "" {
			http.Error(w, "asset_id 必填", http.StatusBadRequest)
			return
		}
		res, err := platform.RunRemoteAudit(r.Context(), db, reg, kr, linuxBin, winBin, tokens,
			req.AssetID, req.Password, req.BaselineID, req.CreatedBy)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, res)
	})

	mux.HandleFunc("/api/v1/agent/download", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path, ok := tokens.Redeem(r.URL.Query().Get("token"))
		if !ok {
			http.Error(w, "令牌无效或已过期", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Disposition", "attachment; filename=medaudit-collector.exe")
		http.ServeFile(w, r, path)
	})
}
