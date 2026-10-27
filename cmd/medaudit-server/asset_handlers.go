package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"medaudit/internal/platform"
)

// 资产登记修正（M6，尤其占位资产）与删除（M17，历史事实包保留）。
func registerAssetRoutes(mux *http.ServeMux, db *sql.DB) {
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
