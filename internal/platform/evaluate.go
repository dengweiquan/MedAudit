package platform

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"medaudit/internal/facts"
	"medaudit/internal/rules"
)

// BaselineRow 基线行。
type BaselineRow struct {
	ID       string `json:"id"`
	Hospital string `json:"hospital_id"`
	Target   string `json:"target"`
	Version  int    `json:"version"`
	Spec     string `json:"spec"`
}

// CreateBaseline 新建基线版本。
func CreateBaseline(db *sql.DB, id, hospitalID, target string, allows []rules.BaselineAllow, createdBy string) error {
	spec, err := json.Marshal(map[string]any{"allows": allows})
	if err != nil {
		return err
	}
	_, err = db.Exec(
		`INSERT INTO baselines (id, hospital_id, target, spec, created_by) VALUES (?, ?, ?, ?, ?)`,
		id, hospitalID, target, string(spec), createdBy)
	return err
}

// LoadBaseline 读取基线并转为 rules.Baseline。
func LoadBaseline(db *sql.DB, id string) (*rules.Baseline, error) {
	var b rules.Baseline
	var target, spec string
	err := db.QueryRow(`SELECT id, target, spec FROM baselines WHERE id = ?`, id).
		Scan(&b.ID, &target, &spec)
	if err != nil {
		return nil, err
	}
	b.Target = facts.TargetType(target)
	var s struct {
		Allows []rules.BaselineAllow `json:"allows"`
	}
	if err := json.Unmarshal([]byte(spec), &s); err != nil {
		return nil, err
	}
	b.Allows = s.Allows
	return &b, nil
}

// ListBaselines 列出基线。
func ListBaselines(db *sql.DB, hospitalID string) ([]BaselineRow, error) {
	rows, err := db.Query(
		`SELECT id, hospital_id, target, version, spec FROM baselines WHERE hospital_id = ? ORDER BY created_at DESC`,
		hospitalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BaselineRow
	for rows.Next() {
		var r BaselineRow
		if err := rows.Scan(&r.ID, &r.Hospital, &r.Target, &r.Version, &r.Spec); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if out == nil {
		out = []BaselineRow{}
	}
	return out, rows.Err()
}

// EvaluationSummary 评估摘要。
type EvaluationSummary struct {
	BundleID      string `json:"bundle_id"`
	Total         int    `json:"total"`
	Pass          int    `json:"pass"`
	Fail          int    `json:"fail"`
	Unknown       int    `json:"unknown"`
	NotApplicable int    `json:"not_applicable"`
	NotRun        int    `json:"not_run"`
	Findings      int    `json:"findings_stored"`
}

// EvaluateBundle 对已导入的事实包执行规则评估，非 PASS 结论存入 findings。
func EvaluateBundle(db *sql.DB, reg *rules.Registry, bundleID, baselineID string) (*EvaluationSummary, error) {
	var raw string
	var hospitalID string
	err := db.QueryRow(`SELECT bundle, hospital_id FROM fact_bundles WHERE id = ?`, bundleID).
		Scan(&raw, &hospitalID)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("事实包 %s 不存在", bundleID)
	}
	if err != nil {
		return nil, err
	}
	var b facts.FactBundle
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return nil, err
	}
	var baseline *rules.Baseline
	if baselineID != "" {
		baseline, err = LoadBaseline(db, baselineID)
		if err != nil {
			return nil, fmt.Errorf("基线加载失败: %w", err)
		}
	} else {
		baseline = &rules.Baseline{}
	}

	results := reg.Evaluate(&b, baseline)
	// M17 本站规则启停：工程师关闭的检查项整体跳过——不计数、不落库、
	// 报告不体现。与基线分工：基线豁免单个主体，启停关闭整项检查。
	disabled, derr := DisabledRuleIDs(db)
	if derr != nil {
		return nil, fmt.Errorf("读取规则启停失败: %w", derr)
	}
	if len(disabled) > 0 {
		kept := results[:0]
		for _, r := range results {
			if !disabled[r.RuleID] {
				kept = append(kept, r)
			}
		}
		results = kept
	}
	summary := &EvaluationSummary{BundleID: bundleID, Total: len(results)}
	for _, r := range results {
		switch r.Conclusion {
		case facts.ConclusionPass:
			summary.Pass++
		case facts.ConclusionFail:
			summary.Fail++
		case facts.ConclusionUnknown:
			summary.Unknown++
		case facts.ConclusionNotApplicable:
			summary.NotApplicable++
		case facts.ConclusionNotRun:
			summary.NotRun++
		}
		if r.Conclusion == facts.ConclusionPass || r.Conclusion == facts.ConclusionNotApplicable {
			continue
		}
		detail, _ := json.Marshal(map[string]any{
			"risk": r.Risk, "detail": r.Detail,
			"evidence": r.Evidence, "missing": r.Missing,
		})
		_, err := db.Exec(
			`INSERT INTO findings (hospital_id, bundle_id, rule_id, rule_version, subject, conclusion, detail)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			hospitalID, bundleID, r.RuleID, r.RuleVersion, r.Subject,
			string(r.Conclusion), string(detail))
		if err != nil {
			return nil, err
		}
		summary.Findings++
	}
	return summary, nil
}

// FindingRow 问题行。
type FindingRow struct {
	ID           int64  `json:"id"`
	BundleID     string `json:"bundle_id"`
	RuleID       string `json:"rule_id"`
	RuleVersion  string `json:"rule_version"`
	Subject      string `json:"subject"`
	Conclusion   string `json:"conclusion"`
	Detail       string `json:"detail"`
	ReviewStatus string `json:"review_status"`
	CreatedAt    string `json:"created_at"`
}

// ListFindings 按 bundle 列出问题。
func ListFindings(db *sql.DB, bundleID string) ([]FindingRow, error) {
	rows, err := db.Query(
		`SELECT id, bundle_id, rule_id, rule_version, subject, conclusion, detail, review_status,
		        strftime('%Y-%m-%d %H:%M:%S', created_at)
		 FROM findings WHERE bundle_id = ? ORDER BY id`, bundleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingRow
	for rows.Next() {
		var f FindingRow
		var detail sql.NullString
		if err := rows.Scan(&f.ID, &f.BundleID, &f.RuleID, &f.RuleVersion,
			&f.Subject, &f.Conclusion, &detail, &f.ReviewStatus, &f.CreatedAt); err != nil {
			return nil, err
		}
		if detail.Valid {
			f.Detail = detail.String
		}
		out = append(out, f)
	}
	if out == nil {
		out = []FindingRow{}
	}
	return out, rows.Err()
}

// ReviewFinding 人工复核：记录决定并更新问题状态。
// decision: confirmed | false_positive | exception
func ReviewFinding(db *sql.DB, findingID int64, hospitalID, decision, comment, reviewer string) error {
	switch decision {
	case "confirmed", "false_positive", "exception":
	default:
		return fmt.Errorf("非法 decision: %s", decision)
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`INSERT INTO reviews (finding_id, hospital_id, decision, comment, reviewer)
		 VALUES (?, ?, ?, ?, ?)`,
		findingID, hospitalID, decision, comment, reviewer); err != nil {
		return err
	}
	status := decision
	if decision == "exception" {
		status = "exception"
	}
	if _, err := tx.Exec(`UPDATE findings SET review_status = ? WHERE id = ?`, status, findingID); err != nil {
		return err
	}
	return tx.Commit()
}
