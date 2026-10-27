package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"medaudit/internal/platform"
)

// 医院登记与删除（M6 登记、M28 级联删除；本站医院不可删，清场走 srvreset）。
func registerHospitalRoutes(mux *http.ServeMux, db *sql.DB) {
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

	// GET /api/v1/hospitals/{id}（登记信息+数据计数）；DELETE 同路径：
	// 删除医院及其全部数据（级联，M28）。本站医院不可删（清场走 srvreset）。
	mux.HandleFunc("/api/v1/hospitals/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/hospitals/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			hs, err := platform.ListHospitals(db)
			if err != nil {
				http.Error(w, "查询失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			var found *platform.Hospital
			for i := range hs {
				if hs[i].ID == id {
					found = &hs[i]
					break
				}
			}
			if found == nil {
				http.Error(w, "医院 "+id+" 不存在", http.StatusNotFound)
				return
			}
			counts, err := platform.HospitalDataCounts(db, id)
			if err != nil {
				http.Error(w, "统计失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]any{"id": found.ID, "name": found.Name, "created_at": found.CreatedAt, "counts": counts})
		case http.MethodDelete:
			if siteHospitalID != "" && id == siteHospitalID {
				http.Error(w, "本站医院不可删除（清场请用 ma srvreset）", http.StatusBadRequest)
				return
			}
			deleted, err := platform.DeleteHospital(db, id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			fmt.Printf("[hospital-delete] 删除医院 %s，行数 %v\n", id, deleted)
			writeJSON(w, map[string]any{"status": "ok", "id": id, "deleted": deleted})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}
