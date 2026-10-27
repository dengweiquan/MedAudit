package platform

import (
	"bytes"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"medaudit/internal/remediation"
)

// ReportRow 报告列表行（M6）。bundle_id 与结论摘要自快照 JSON 提取。
type ReportRow struct {
	ID                string          `json:"id"`
	HospitalID        string          `json:"hospital_id"`
	PlanID            string          `json:"plan_id"`
	BundleID          string          `json:"bundle_id"`
	CreatedBy         string          `json:"created_by"`
	CreatedAt         string          `json:"created_at"`
	ConclusionSummary json.RawMessage `json:"conclusion_summary,omitempty"`
}

// ListReports 列出全部报告（新→旧）。
func ListReports(db *sql.DB) ([]ReportRow, error) {
	rows, err := db.Query(
		`SELECT id, hospital_id, plan_id,
		        COALESCE(json_extract(snapshot, '$.bundle_id'), ''),
		        created_by, created_at,
		        json_extract(snapshot, '$.conclusion_summary')
		 FROM reports ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReportRow{}
	for rows.Next() {
		var r ReportRow
		var summary sql.NullString
		if err := rows.Scan(&r.ID, &r.HospitalID, &r.PlanID, &r.BundleID,
			&r.CreatedBy, &r.CreatedAt, &summary); err != nil {
			return nil, err
		}
		if summary.Valid && summary.String != "" && summary.String != "null" {
			r.ConclusionSummary = json.RawMessage(summary.String)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ReportCSV 把报告快照内的问题清单导为 CSV（UTF-8 BOM，便于 Excel 直接打开）。
func ReportCSV(db *sql.DB, reportID string) ([]byte, error) {
	snap, err := GetReportSnapshot(db, reportID)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Findings    []FindingRow `json:"findings"`
		Remediation *struct {
			Scripts []remediation.Script `json:"scripts"`
		} `json:"remediation"`
	}
	if err := json.Unmarshal([]byte(snap), &parsed); err != nil {
		return nil, fmt.Errorf("报告快照解析失败: %w", err)
	}
	var buf bytes.Buffer
	buf.WriteString("\ufeff")
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"finding_id", "rule_id", "rule_version", "subject", "conclusion", "review_status", "detail", "created_at", "fix_command", "rollback_command"})
	scriptsByFinding := map[int64]remediation.Script{}
	if parsed.Remediation != nil {
		for _, sc := range parsed.Remediation.Scripts {
			scriptsByFinding[sc.FindingID] = sc
		}
	}
	for _, f := range parsed.Findings {
		sc := scriptsByFinding[f.ID]
		_ = w.Write([]string{
			fmt.Sprint(f.ID), f.RuleID, f.RuleVersion, f.Subject,
			f.Conclusion, f.ReviewStatus, f.Detail, f.CreatedAt,
			sc.Fix, sc.Rollback,
		})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
