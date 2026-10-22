package main

import (
	"database/sql"
	"net/http"
	"strings"

	"medaudit/internal/platform"
)

// 报告读取与 Word 导出（M4-4a/d）：
// GET /api/v1/reports/{id}        → 快照 JSON
// GET /api/v1/reports/{id}/docx   → Word 文档
func registerReportReadRoutes(mux *http.ServeMux, db *sql.DB) {
	mux.HandleFunc("/api/v1/reports/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/reports/")
		id := rest
		wantDocx := false
		wantCSV := false
		if strings.HasSuffix(rest, "/docx") {
			id = strings.TrimSuffix(rest, "/docx")
			wantDocx = true
		}
		if strings.HasSuffix(rest, "/csv") {
			id = strings.TrimSuffix(rest, "/csv")
			wantCSV = true
		}
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		if wantCSV {
			data, err := platform.ReportCSV(db, id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			w.Header().Set("Content-Disposition", "attachment; filename="+id+".csv")
			_, _ = w.Write(data)
			return
		}
		snap, err := platform.GetReportSnapshot(db, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if !wantDocx {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(snap))
			return
		}
		docx, err := platform.RenderReportDocx(snap, id)
		if err != nil {
			http.Error(w, "Word 渲染失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
		w.Header().Set("Content-Disposition", "attachment; filename="+id+".docx")
		_, _ = w.Write(docx)
	})
}
