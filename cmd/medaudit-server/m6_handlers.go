package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"medaudit/internal/platform"
	"medaudit/internal/rules"
)

// M6 新增路由：医院登记、资产登记修正、一键审计。
// （资产新建 POST /api/v1/assets 在 main.go 的方法分发里；问题复测/整改在 eval_handlers.go 分发里。）
func registerM6Routes(mux *http.ServeMux, db *sql.DB, reg *rules.Registry, kr *platform.EvidenceKeyring, collectorBin string) {
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

	// GET /api/v1/hospitals；POST /api/v1/hospitals {id, name}
	mux.HandleFunc("/api/v1/hospitals", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			rows, err := platform.ListHospitals(db)
			if err != nil {
				http.Error(w, "查询失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, rows)
		case http.MethodPost:
			var req struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "请求解析失败", http.StatusBadRequest)
				return
			}
			if err := platform.CreateHospital(db, req.ID, req.Name); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, map[string]string{"status": "ok", "id": req.ID})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// PUT /api/v1/assets/{id} {kind, name, endpoint}：修正资产登记（尤其占位资产）。
	mux.HandleFunc("/api/v1/assets/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/assets/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		// DELETE /api/v1/assets/{id}：删除资产登记（M17，历史事实包保留）
		if r.Method == http.MethodDelete {
			if err := platform.DeleteAsset(db, id); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]string{"status": "ok", "id": id})
			return
		}
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Kind     string  `json:"kind"`
			Name     string  `json:"name"`
			Endpoint *string `json:"endpoint"`
			Labels   *string `json:"labels"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "请求解析失败", http.StatusBadRequest)
			return
		}
		if err := platform.UpdateAsset(db, id, req.Kind, req.Name, req.Endpoint, req.Labels); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]string{"status": "ok", "id": id})
	})
}
