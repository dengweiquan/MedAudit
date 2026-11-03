package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"medaudit/internal/apiaudit"
	"medaudit/internal/platform"
)

// 业务接口越权检测报告的存档与查询（M4-1，M4-4 合规绑定）。
// 报告由 medaudit-collector apicheck 生成后上传；结论逐项保存在 report JSON 中。
// 服务端不信任客户端汇总：存档统计由 checks 重算；绑定（医院/资产）须经库核实，
// 否则拒绝上传。机器通道（POST）无浏览器会话，故权限与归属的核验即这两项
// （绑定存在性与一致性 + 统计重算），而非用户身份。

type apiAuditSummary struct {
	ReportID     string `json:"report_id"`
	Target       string `json:"target"`
	Execution    string `json:"execution"`
	HospitalID   string `json:"hospital_id,omitempty"`
	AssetID      string `json:"asset_id,omitempty"`
	Total        int    `json:"total"`
	PassCount    int    `json:"pass_count"`
	FailCount    int    `json:"fail_count"`
	UnknownCount int    `json:"unknown_count"`
	NotRunCount  int    `json:"not_run_count"`
	ImportedAt   string `json:"imported_at"`
}

// verifyAPIAuditBinding 核实报告的医院/资产绑定：资产须存在且归属该医院；
// 只有医院无资产时核实医院存在。未绑定（两列均空）不报错，仅不用于合规判定。
func verifyAPIAuditBinding(db *sql.DB, hospitalID, assetID string) error {
	if assetID != "" {
		var hosp string
		err := db.QueryRow(`SELECT hospital_id FROM assets WHERE id = ?`, assetID).Scan(&hosp)
		if err == sql.ErrNoRows {
			return errBindingAssetMissing
		}
		if err != nil {
			return err
		}
		if hospitalID != "" && hosp != hospitalID {
			return errBindingHospitalMismatch
		}
		return nil
	}
	if hospitalID != "" {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM hospitals WHERE id = ?`, hospitalID).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return errBindingHospitalMissing
		}
	}
	return nil
}

var (
	errBindingAssetMissing     = errString("绑定资产不存在")
	errBindingHospitalMismatch = errString("绑定资产不归属该医院")
	errBindingHospitalMissing  = errString("绑定医院不存在")
)

type errString string

func (e errString) Error() string { return string(e) }

func registerAPIAuditRoutes(mux *http.ServeMux, db *sql.DB) {
	mux.HandleFunc("/api/v1/api-audits", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			raw, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
			if err != nil {
				http.Error(w, "读取报告失败", http.StatusBadRequest)
				return
			}
			var rep apiaudit.Report
			if err := json.Unmarshal(raw, &rep); err != nil || rep.ReportID == "" || rep.Target == "" {
				http.Error(w, "报告格式非法（需含 report_id/target）", http.StatusBadRequest)
				return
			}
			// 服务端重算统计，不信任客户端 Summary；存档归一化后的报告。
			rep.Summary = platform.CountAPIAuditSummary(rep.Checks)
			normalized, err := json.Marshal(rep)
			if err != nil {
				http.Error(w, "报告编码失败", http.StatusInternalServerError)
				return
			}
			if err := verifyAPIAuditBinding(db, rep.HospitalID, rep.AssetID); err != nil {
				switch err {
				case errBindingAssetMissing, errBindingHospitalMismatch, errBindingHospitalMissing:
					http.Error(w, "绑定校验失败："+err.Error(), http.StatusBadRequest)
				default:
					http.Error(w, "查询失败: "+err.Error(), http.StatusInternalServerError)
				}
				return
			}
			var exists int
			if err := db.QueryRow(`SELECT COUNT(*) FROM api_audit_reports WHERE report_id = ?`, rep.ReportID).Scan(&exists); err != nil {
				http.Error(w, "查询失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if exists > 0 {
				writeJSON(w, map[string]any{"report_id": rep.ReportID, "status": "duplicate"})
				return
			}
			_, err = db.Exec(
				`INSERT INTO api_audit_reports (report_id, target, execution, hospital_id, asset_id, total, pass_count, fail_count, unknown_count, not_run_count, report)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				rep.ReportID, rep.Target, rep.Execution, rep.HospitalID, rep.AssetID, len(rep.Checks),
				rep.Summary["PASS"], rep.Summary["FAIL"], rep.Summary["UNKNOWN"], rep.Summary["NOT_RUN"],
				string(normalized))
			if err != nil {
				http.Error(w, "存档失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, map[string]any{"report_id": rep.ReportID, "status": "stored"})
		case http.MethodGet:
			rows, err := db.Query(
				`SELECT report_id, target, execution, hospital_id, asset_id, total, pass_count, fail_count, unknown_count, not_run_count,
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
				if err := rows.Scan(&s.ReportID, &s.Target, &s.Execution, &s.HospitalID, &s.AssetID, &s.Total,
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
		wantCompliance := strings.HasSuffix(rest, "/compliance")
		id := rest
		if wantDocx {
			id = strings.TrimSuffix(rest, "/docx")
		} else if wantCompliance {
			id = strings.TrimSuffix(rest, "/compliance")
		}
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
		if wantCompliance {
			// 合规判定（医疗-12）：绑定资产须在库中存在且归属报告医院，否则不评估。
			var rep apiaudit.Report
			assetVerified := false
			if err := json.Unmarshal([]byte(raw), &rep); err == nil && rep.HospitalID != "" && rep.AssetID != "" {
				var hosp string
				if err := db.QueryRow(`SELECT hospital_id FROM assets WHERE id = ?`, rep.AssetID).Scan(&hosp); err == nil && hosp == rep.HospitalID {
					assetVerified = true
				}
			}
			res, err := platform.APICompliance([]byte(raw), assetVerified)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, res)
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
