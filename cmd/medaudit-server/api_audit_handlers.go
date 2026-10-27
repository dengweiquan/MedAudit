package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"medaudit/internal/platform"
)

// 业务接口越权检测报告的存档与查询（M4-1）。
// 报告由 medaudit-collector apicheck 生成后上传；结论逐项保存在 report JSON 中。

type apiAuditSummary struct {
	ReportID     string `json:"report_id"`
	Target       string `json:"target"`
	Execution    string `json:"execution"`
	Total        int    `json:"total"`
	PassCount    int    `json:"pass_count"`
	FailCount    int    `json:"fail_count"`
	UnknownCount int    `json:"unknown_count"`
	NotRunCount  int    `json:"not_run_count"`
	ImportedAt   string `json:"imported_at"`
}

type apiAuditReportHead struct {
	ReportID  string            `json:"report_id"`
	Target    string            `json:"target"`
	Execution string            `json:"execution"`
	Summary   map[string]int    `json:"summary"`
	Checks    []json.RawMessage `json:"checks"`
}

func registerAPIAuditRoutes(mux *http.ServeMux, db *sql.DB) {
	mux.HandleFunc("/api/v1/api-audits", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var head apiAuditReportHead
			raw, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
			if err != nil {
				http.Error(w, "读取报告失败", http.StatusBadRequest)
				return
			}
			if err := json.Unmarshal(raw, &head); err != nil || head.ReportID == "" || head.Target == "" {
				http.Error(w, "报告格式非法（需含 report_id/target）", http.StatusBadRequest)
				return
			}
			var exists int
			if err := db.QueryRow(`SELECT COUNT(*) FROM api_audit_reports WHERE report_id = ?`, head.ReportID).Scan(&exists); err != nil {
				http.Error(w, "查询失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if exists > 0 {
				writeJSON(w, map[string]any{"report_id": head.ReportID, "status": "duplicate"})
				return
			}
			_, err = db.Exec(
				`INSERT INTO api_audit_reports (report_id, target, execution, total, pass_count, fail_count, unknown_count, not_run_count, report)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				head.ReportID, head.Target, head.Execution, len(head.Checks),
				head.Summary["PASS"], head.Summary["FAIL"], head.Summary["UNKNOWN"], head.Summary["NOT_RUN"],
				string(raw))
			if err != nil {
				http.Error(w, "存档失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, map[string]any{"report_id": head.ReportID, "status": "stored"})
		case http.MethodGet:
			rows, err := db.Query(
				`SELECT report_id, target, execution, total, pass_count, fail_count, unknown_count, not_run_count,
				        strftime('%Y-%m-%d %H:%M:%S', imported_at)
				 FROM api_audit_reports ORDER BY imported_at DESC LIMIT 100`)
			if err != nil {
				http.Error(w, "查询失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			defer rows.Close()
			out := []apiAuditSummary{}
			for rows.Next() {
				var s apiAuditSummary
				if err := rows.Scan(&s.ReportID, &s.Target, &s.Execution, &s.Total,
					&s.PassCount, &s.FailCount, &s.UnknownCount, &s.NotRunCount, &s.ImportedAt); err != nil {
					http.Error(w, "读取失败: "+err.Error(), http.StatusInternalServerError)
					return
				}
				out = append(out, s)
			}
			writeJSON(w, out)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/v1/api-audits/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/api-audits/")
		wantDocx := strings.HasSuffix(rest, "/docx")
		id := strings.TrimSuffix(rest, "/docx")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		var raw string
		err := db.QueryRow(`SELECT report FROM api_audit_reports WHERE report_id = ?`, id).Scan(&raw)
		if err == sql.ErrNoRows {
			http.Error(w, "报告不存在", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "查询失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if wantDocx {
			docx, err := platform.RenderAPIAuditDocx(raw)
			if err != nil {
				http.Error(w, "Word 生成失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
			w.Header().Set("Content-Disposition", "attachment; filename="+id+".docx")
			_, _ = w.Write(docx)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(raw))
	})
}
