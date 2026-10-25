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

// UpdateBaselineAllows 整体替换基线的放行项（基线页编辑），版本号 +1。
// ID、医院、目标锁定不变；重复放行项按四元组去重；已存问题与报告不动。
func UpdateBaselineAllows(db *sql.DB, id string, allows []rules.BaselineAllow) error {
	spec, err := json.Marshal(map[string]any{"allows": dedupeAllows(allows)})
	if err != nil {
		return err
	}
	res, err := db.Exec(`UPDATE baselines SET spec = ?, version = version + 1 WHERE id = ?`, string(spec), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("基线不存在: %s", id)
	}
	return nil
}

// DeleteBaseline 删除整条基线（基线页删除）；仅影响以后评估，已存问题与报告不动。
func DeleteBaseline(db *sql.DB, id string) error {
	res, err := db.Exec(`DELETE FROM baselines WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("基线不存在: %s", id)
	}
	return nil
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
	BundleID         string   `json:"bundle_id"`
	Total            int      `json:"total"`
	Pass             int      `json:"pass"`
	Fail             int      `json:"fail"`
	Unknown          int      `json:"unknown"`
	NotApplicable    int      `json:"not_applicable"`
	NotRun           int      `json:"not_run"`
	Findings         int      `json:"findings_stored"`
	BaselineMode     string   `json:"baseline_mode"`              // auto | baseline | bare
	BaselinesApplied []string `json:"baselines_applied,omitempty"` // 本次实际套用的基线 ID
}

// EvaluateBundle 对已导入的事实包执行规则评估，非 PASS 结论存入 findings。
// baselineID 为空 = 裸评；指定 ID = 只用该基线。远程审计等显式调用走本函数，
// 语义不变；在线评估（Web/ma 默认）走 EvaluateBundleAuto。
func EvaluateBundle(db *sql.DB, reg *rules.Registry, bundleID, baselineID string) (*EvaluationSummary, error) {
	raw, hospitalID, _, err := loadBundleMeta(db, bundleID)
	if err != nil {
		return nil, err
	}
	var baseline *rules.Baseline
	mode := "bare"
	if baselineID != "" {
		baseline, err = LoadBaseline(db, baselineID)
		if err != nil {
			return nil, fmt.Errorf("基线加载失败: %w", err)
		}
		mode = "baseline"
	} else {
		baseline = &rules.Baseline{}
	}
	return evaluateCore(db, reg, bundleID, raw, hospitalID, baseline, mode, nil)
}

// EvaluateBundleAuto 在线评估（M35 自动屏蔽）：
//   baselineID 指定 → 只用该基线（显式选择，语义不变）；
//   bare=true → 裸评（不套用任何基线，保留裸评对比）；
//   否则 → 自动套用该包所属医院的全部基线（目标匹配者），加基线后默认屏蔽。
func EvaluateBundleAuto(db *sql.DB, reg *rules.Registry, bundleID, baselineID string, bare bool) (*EvaluationSummary, error) {
	raw, hospitalID, assetID, err := loadBundleMeta(db, bundleID)
	if err != nil {
		return nil, err
	}
	var baseline *rules.Baseline
	mode := "auto"
	var applied []string
	switch {
	case baselineID != "":
		baseline, err = LoadBaseline(db, baselineID)
		if err != nil {
			return nil, fmt.Errorf("基线加载失败: %w", err)
		}
		mode = "baseline"
		applied = []string{baselineID}
	case bare:
		baseline = &rules.Baseline{}
		mode = "bare"
	default:
		kind := ""
		if assetID != "" {
			_ = db.QueryRow(`SELECT kind FROM assets WHERE id = ?`, assetID).Scan(&kind)
		}
		baseline, applied, err = LoadHospitalBaselines(db, hospitalID, kind)
		if err != nil {
			return nil, err
		}
	}
	return evaluateCore(db, reg, bundleID, raw, hospitalID, baseline, mode, applied)
}

// loadBundleMeta 取包 JSON、医院、资产。
func loadBundleMeta(db *sql.DB, bundleID string) (raw, hospitalID, assetID string, err error) {
	err = db.QueryRow(`SELECT bundle, hospital_id, asset_id FROM fact_bundles WHERE id = ?`, bundleID).
		Scan(&raw, &hospitalID, &assetID)
	if err == sql.ErrNoRows {
		return "", "", "", fmt.Errorf("事实包 %s 不存在", bundleID)
	}
	return raw, hospitalID, assetID, err
}

// LoadHospitalBaselines 合并某医院的全部基线（目标为空或与资产类型匹配者），
// 返回合并后的基线与实际套用的基线 ID（去重后放行项合并）。
func LoadHospitalBaselines(db *sql.DB, hospitalID, target string) (*rules.Baseline, []string, error) {
	rows, err := db.Query(`SELECT id, target, spec FROM baselines WHERE hospital_id = ? ORDER BY id`, hospitalID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	merged := &rules.Baseline{}
	var applied []string
	for rows.Next() {
		var id, tgt, spec string
		if err := rows.Scan(&id, &tgt, &spec); err != nil {
			return nil, nil, err
		}
		if tgt != "" && target != "" && tgt != target {
			continue
		}
		var s struct {
			Allows []rules.BaselineAllow `json:"allows"`
		}
		if err := json.Unmarshal([]byte(spec), &s); err != nil {
			return nil, nil, err
		}
		merged.Allows = append(merged.Allows, s.Allows...)
		applied = append(applied, id)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	merged.Allows = dedupeAllows(merged.Allows)
	return merged, applied, nil
}

// evaluateCore 评估公共核心：规则评估 + 本站启停过滤 + 落库。
func evaluateCore(db *sql.DB, reg *rules.Registry, bundleID, raw, hospitalID string, baseline *rules.Baseline, mode string, applied []string) (*EvaluationSummary, error) {
	var b facts.FactBundle
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return nil, err
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
	summary := &EvaluationSummary{BundleID: bundleID, Total: len(results), BaselineMode: mode, BaselinesApplied: applied}
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
