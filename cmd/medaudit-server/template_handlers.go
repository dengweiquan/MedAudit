package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"medaudit/internal/platform"
	"medaudit/internal/rules"
)

// registerTemplateRoutes 基线模板：
//   - GET  /api/v1/baseline-templates              模板列表（内置 + 站点目录）
//   - POST /api/v1/baseline-templates/{id}/apply   套用到基线并重评该医院同类对象最新审计
func registerTemplateRoutes(mux *http.ServeMux, db *sql.DB, reg *rules.Registry, sessions *platform.SessionStore) {
	mux.HandleFunc("/api/v1/baseline-templates", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		list, errs := platform.ListBaselineTemplates()
		if errs == nil {
			errs = []string{}
		}
		writeJSON(w, map[string]any{"items": list, "errors": errs})
	})
	mux.HandleFunc("/api/v1/baseline-templates/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/baseline-templates/")
		id := strings.TrimSuffix(rest, "/apply")
		if r.Method != http.MethodPost || !strings.HasSuffix(rest, "/apply") || id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		var req platform.TemplateApply
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "请求解析失败", http.StatusBadRequest)
			return
		}
		if req.CreatedBy == "" {
			req.CreatedBy = currentUser(r, sessions)
		}
		added, created, err := platform.ApplyBaselineTemplate(db, id, req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var target string
		_ = db.QueryRow(`SELECT target FROM baselines WHERE id = ?`, req.BaselineID).Scan(&target)
		n, err := platform.ReevaluateLatest(db, reg, req.HospitalID, target)
		resp := map[string]any{"baseline_id": req.BaselineID, "created": created, "added": len(added), "reevaluated": n}
		if err != nil {
			resp["reevaluate_error"] = err.Error()
		}
		writeJSON(w, resp)
	})
}
