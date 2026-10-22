package platform

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"medaudit/internal/facts"
	"medaudit/internal/rules"
)

// RetestRow 复测记录（M6）。
type RetestRow struct {
	ID         int64  `json:"id"`
	FindingID  int64  `json:"finding_id"`
	HospitalID string `json:"hospital_id"`
	BundleID   string `json:"bundle_id"`
	Conclusion string `json:"conclusion"`
	CreatedAt  string `json:"created_at"`
}

// RetestFinding 以新事实包对某条问题做复测：
//   - 新包必须与原包属于同一资产（复测语义：同目标重新采集）；
//   - 以新包做技术口径（无基线）重评估，按 rule_id + subject 比对：
//     仍有非 PASS 结论 → 取最严重者；无匹配或仅 PASS/NOT_APPLICABLE → PASS。
//
// 结论写入 retests 表并返回该行。技术结论与人工复核状态分离（不改 findings.review_status）。
func RetestFinding(db *sql.DB, reg *rules.Registry, findingID int64, newBundleID string) (*RetestRow, error) {
	var ruleID, subject, hospitalID, origBundleID string
	err := db.QueryRow(
		`SELECT rule_id, subject, hospital_id, bundle_id FROM findings WHERE id = ?`, findingID,
	).Scan(&ruleID, &subject, &hospitalID, &origBundleID)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("问题 %d 不存在", findingID)
	}
	if err != nil {
		return nil, err
	}
	var origAsset, newAsset, newRaw string
	if err := db.QueryRow(`SELECT asset_id FROM fact_bundles WHERE id = ?`, origBundleID).Scan(&origAsset); err != nil {
		return nil, fmt.Errorf("原事实包 %s 不存在", origBundleID)
	}
	err = db.QueryRow(`SELECT asset_id, bundle FROM fact_bundles WHERE id = ?`, newBundleID).Scan(&newAsset, &newRaw)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("复测事实包 %s 不存在", newBundleID)
	}
	if err != nil {
		return nil, err
	}
	if newAsset != origAsset {
		return nil, fmt.Errorf("复测包资产 %s 与原包资产 %s 不一致，不能复测", newAsset, origAsset)
	}
	var b facts.FactBundle
	if err := json.Unmarshal([]byte(newRaw), &b); err != nil {
		return nil, fmt.Errorf("复测包解析失败: %w", err)
	}
	if off, derr := IsRuleDisabled(db, ruleID); derr != nil {
		return nil, fmt.Errorf("读取规则启停失败: %w", derr)
	} else if off {
		return nil, fmt.Errorf("检查项 %s 已被工程师关闭（本站），复测不适用", ruleID)
	}
	results := reg.Evaluate(&b, &rules.Baseline{})
	// 严重程度排序：FAIL > UNKNOWN > NOT_RUN > PASS/NOT_APPLICABLE
	rank := map[facts.Conclusion]int{
		facts.ConclusionFail: 4, facts.ConclusionUnknown: 3, facts.ConclusionNotRun: 2,
		facts.ConclusionPass: 1, facts.ConclusionNotApplicable: 0,
	}
	conclusion := facts.ConclusionPass
	worst := 0
	for _, r := range results {
		if r.RuleID != ruleID || r.Subject != subject {
			continue
		}
		if rk := rank[r.Conclusion]; rk > worst {
			worst = rk
			conclusion = r.Conclusion
		}
	}
	if conclusion == facts.ConclusionNotApplicable {
		conclusion = facts.ConclusionPass
	}
	res, err := db.Exec(
		`INSERT INTO retests (hospital_id, finding_id, bundle_id, conclusion) VALUES (?, ?, ?, ?)`,
		hospitalID, findingID, newBundleID, string(conclusion))
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	row := &RetestRow{FindingID: findingID, HospitalID: hospitalID, BundleID: newBundleID,
		Conclusion: string(conclusion)}
	if err := db.QueryRow(
		`SELECT id, created_at FROM retests WHERE id = ?`, id,
	).Scan(&row.ID, &row.CreatedAt); err != nil {
		return nil, err
	}
	return row, nil
}

// ListRetests 列出某个问题的全部复测历史（新→旧）。
func ListRetests(db *sql.DB, findingID int64) ([]RetestRow, error) {
	rows, err := db.Query(
		`SELECT id, finding_id, hospital_id, bundle_id, conclusion, created_at
		 FROM retests WHERE finding_id = ? ORDER BY id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RetestRow{}
	for rows.Next() {
		var r RetestRow
		if err := rows.Scan(&r.ID, &r.FindingID, &r.HospitalID, &r.BundleID, &r.Conclusion, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RemediationRow 整改记录（M6）。
type RemediationRow struct {
	ID         int64   `json:"id"`
	FindingID  int64   `json:"finding_id"`
	HospitalID string  `json:"hospital_id"`
	Action     string  `json:"action"`
	Status     string  `json:"status"`
	ActedBy    string  `json:"acted_by"`
	ActedAt    *string `json:"acted_at"`
	CreatedAt  string  `json:"created_at"`
}

// AddRemediation 登记一条整改记录；status 为 done 时自动记 acted_at。
func AddRemediation(db *sql.DB, findingID int64, action, status, actedBy string) (*RemediationRow, error) {
	if strings.TrimSpace(action) == "" || strings.TrimSpace(actedBy) == "" {
		return nil, fmt.Errorf("action 与 acted_by 必填")
	}
	if status == "" {
		status = "pending"
	}
	if status != "pending" && status != "done" {
		return nil, fmt.Errorf("非法 status: %s（pending/done）", status)
	}
	var hospitalID string
	err := db.QueryRow(`SELECT hospital_id FROM findings WHERE id = ?`, findingID).Scan(&hospitalID)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("问题 %d 不存在", findingID)
	}
	if err != nil {
		return nil, err
	}
	res, err := db.Exec(
		`INSERT INTO remediations (hospital_id, finding_id, action, status, acted_by, acted_at)
		 VALUES (?, ?, ?, ?, ?, CASE WHEN ? = 'done' THEN CURRENT_TIMESTAMP ELSE NULL END)`,
		hospitalID, findingID, action, status, actedBy, status)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	rows, err := ListRemediations(db, findingID)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].ID == id {
			return &rows[i], nil
		}
	}
	return nil, fmt.Errorf("整改记录 %d 写入后读取失败", id)
}

// ListRemediations 列出某个问题的全部整改记录（新→旧）。
func ListRemediations(db *sql.DB, findingID int64) ([]RemediationRow, error) {
	rows, err := db.Query(
		`SELECT id, finding_id, hospital_id, action, status, acted_by, acted_at, created_at
		 FROM remediations WHERE finding_id = ? ORDER BY id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RemediationRow{}
	for rows.Next() {
		var r RemediationRow
		if err := rows.Scan(&r.ID, &r.FindingID, &r.HospitalID, &r.Action, &r.Status,
			&r.ActedBy, &r.ActedAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
