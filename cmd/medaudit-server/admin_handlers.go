package main

import (
	"database/sql"
	"fmt"
	"net/http"

	"medaudit/internal/platform"
)

// 管理运维接口（M27）。
func registerAdminRoutes(mux *http.ServeMux, db *sql.DB, sessions *platform.SessionStore) {
	// POST /api/v1/admin/wipe：一键清除全部业务信息（新客户现场交接）。
	// 清场后：用户恢复为默认 admin（首登强制改密）、全部会话吊销、
	// 本站医院（若有配置）重新登记。调用方（ma srvreset）负责先备份；
	// 许可文件与服务端配置不在清除范围。
	mux.HandleFunc("/api/v1/admin/wipe", func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			http.Error(w, "平台库未配置", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		by := currentUser(r, sessions)
		deleted, err := platform.WipeAllData(db)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sessions.Clear()
		initSiteHospital(db)
		fmt.Printf("[admin-wipe] 用户 %s 执行一键清场，删除行数 %v\n", by, deleted)
		writeJSON(w, map[string]any{"status": "ok", "deleted": deleted, "site_hospital": siteHospitalID})
	})
}
