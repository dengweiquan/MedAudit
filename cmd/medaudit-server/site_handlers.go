package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"

	"medaudit/internal/platform"
)

// 本站医院（M17 修正：单院部署——一个部署只服务一家医院，
// 医院在初始化时给定，不做多医院管理）。
// 环境变量 MEDAUDIT_SITE_HOSPITAL_ID / MEDAUDIT_SITE_HOSPITAL_NAME 由
// 安装初始化（install.sh）写入服务端环境；启动时医院不存在则创建，
// 已存在则以库内登记为准（不覆盖名称）。
var siteHospitalID string

func initSiteHospital(db *sql.DB) {
	siteHospitalID = os.Getenv("MEDAUDIT_SITE_HOSPITAL_ID")
	if db == nil || siteHospitalID == "" {
		return
	}
	name := os.Getenv("MEDAUDIT_SITE_HOSPITAL_NAME")
	if name == "" {
		name = siteHospitalID
	}
	if hs, err := platform.ListHospitals(db); err == nil {
		for _, h := range hs {
			if h.ID == siteHospitalID {
				fmt.Println("本站医院:", h.ID, h.Name)
				return
			}
		}
	}
	if err := platform.CreateHospital(db, siteHospitalID, name); err != nil {
		fmt.Println("本站医院初始化失败:", err)
		return
	}
	fmt.Println("本站医院已初始化:", siteHospitalID, name)
}

func registerSiteRoutes(mux *http.ServeMux, db *sql.DB) {
	// GET /api/v1/site → 本站医院；未初始化（开发/多院测试实例）时 hospital_id 为空。
	mux.HandleFunc("/api/v1/site", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{"hospital_id": "", "name": ""}
		if siteHospitalID != "" {
			resp["hospital_id"] = siteHospitalID
			resp["name"] = siteHospitalID
			if db != nil {
				if hs, err := platform.ListHospitals(db); err == nil {
					for _, h := range hs {
						if h.ID == siteHospitalID {
							resp["name"] = h.Name
						}
					}
				}
			}
		}
		writeJSON(w, resp)
	})
}
