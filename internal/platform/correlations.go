package platform

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"medaudit/internal/correlation"
	"medaudit/internal/facts"
)

// CorrelationSummary 关联报告列表项。
type CorrelationSummary struct {
	ReportID   string   `json:"report_id"`
	HospitalID string   `json:"hospital_id"`
	BundleIDs  []string `json:"bundle_ids"`
	PathCount  int      `json:"path_count"`
	CreatedBy  string   `json:"created_by,omitempty"`
	CreatedAt  string   `json:"created_at"`
}

// CorrelationDetail 关联报告详情。
type CorrelationDetail struct {
	CorrelationSummary
	Result correlation.Report `json:"result"`
}

func loadBundle(db *sql.DB, bundleID string) (*facts.FactBundle, error) {
	var raw string
	err := db.QueryRow(`SELECT bundle FROM fact_bundles WHERE id = ?`, bundleID).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("事实包 %s 不存在", bundleID)
	}
	if err != nil {
		return nil, err
	}
	var b facts.FactBundle
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return nil, fmt.Errorf("事实包 %s 解析失败: %w", bundleID, err)
	}
	return &b, nil
}

// RunCorrelation 对一组同医院事实包做跨层路径关联分析并存档。
func RunCorrelation(db *sql.DB, bundleIDs []string, createdBy string) (*CorrelationDetail, error) {
	if len(bundleIDs) < 2 {
		return nil, fmt.Errorf("关联分析至少需要 2 个事实包")
	}
	if len(bundleIDs) > 12 {
		return nil, fmt.Errorf("单次关联的事实包不能超过 12 个")
	}
	inputs := make([]correlation.BundleInput, 0, len(bundleIDs))
	hospital := ""
	for _, id := range bundleIDs {
		b, err := loadBundle(db, id)
		if err != nil {
			return nil, err
		}
		if hospital == "" {
			hospital = b.Scope.HospitalID
		} else if b.Scope.HospitalID != hospital {
			return nil, fmt.Errorf("事实包 %s 属于医院 %s，与 %s 不一致，跨医院不能关联", id, b.Scope.HospitalID, hospital)
		}
		inputs = append(inputs, correlation.BundleInput{
			BundleID: b.BundleID,
			Adapter:  string(b.Collector.Adapter),
			AssetID:  b.Scope.AssetID,
			Hospital: b.Scope.HospitalID,
			Facts:    b.Facts,
		})
	}
	rep := correlation.Analyze(inputs)
	if rep.Paths == nil {
		rep.Paths = []correlation.PathResult{}
	}
	rnd := make([]byte, 3)
	_, _ = rand.Read(rnd)
	reportID := fmt.Sprintf("corr-%s-%s", time.Now().UTC().Format("20060102-150405"), hex.EncodeToString(rnd))
	idsJSON, _ := json.Marshal(bundleIDs)
	repJSON, _ := json.Marshal(rep)
	if _, err := db.Exec(
		`INSERT INTO correlation_reports (report_id, hospital_id, bundle_ids, path_count, report, created_by)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		reportID, hospital, string(idsJSON), len(rep.Paths), string(repJSON), createdBy); err != nil {
		return nil, fmt.Errorf("保存关联报告失败: %w", err)
	}
	return &CorrelationDetail{
		CorrelationSummary: CorrelationSummary{
			ReportID: reportID, HospitalID: hospital, BundleIDs: bundleIDs,
			PathCount: len(rep.Paths), CreatedBy: createdBy,
			CreatedAt: time.Now().UTC().Format("2006-01-02 15:04:05"),
		},
		Result: *rep,
	}, nil
}

// ListCorrelations 关联报告列表（新→旧）。
func ListCorrelations(db *sql.DB) ([]CorrelationSummary, error) {
	rows, err := db.Query(
		`SELECT report_id, hospital_id, bundle_ids, path_count, COALESCE(created_by,''), created_at
		 FROM correlation_reports ORDER BY created_at DESC, report_id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CorrelationSummary{}
	for rows.Next() {
		var s CorrelationSummary
		var ids string
		if err := rows.Scan(&s.ReportID, &s.HospitalID, &ids, &s.PathCount, &s.CreatedBy, &s.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(ids), &s.BundleIDs)
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetCorrelation 关联报告详情。
func GetCorrelation(db *sql.DB, reportID string) (*CorrelationDetail, error) {
	var s CorrelationSummary
	var ids, repJSON string
	err := db.QueryRow(
		`SELECT report_id, hospital_id, bundle_ids, path_count, COALESCE(created_by,''), created_at, report
		 FROM correlation_reports WHERE report_id = ?`, reportID).
		Scan(&s.ReportID, &s.HospitalID, &ids, &s.PathCount, &s.CreatedBy, &s.CreatedAt, &repJSON)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("关联报告 %s 不存在", reportID)
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(ids), &s.BundleIDs)
	var rep correlation.Report
	if err := json.Unmarshal([]byte(repJSON), &rep); err != nil {
		return nil, err
	}
	if rep.Paths == nil {
		rep.Paths = []correlation.PathResult{}
	}
	return &CorrelationDetail{CorrelationSummary: s, Result: rep}, nil
}
