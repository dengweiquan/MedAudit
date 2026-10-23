package platform

import (
	"database/sql"
	"fmt"
	"strings"
)

// ---- 医院登记（M6） ----

// Hospital 医院登记行。
type Hospital struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

// ListHospitals 列出全部医院。
func ListHospitals(db *sql.DB) ([]Hospital, error) {
	rows, err := db.Query(`SELECT id, name, created_at FROM hospitals ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Hospital{}
	for rows.Next() {
		var h Hospital
		if err := rows.Scan(&h.ID, &h.Name, &h.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// CreateHospital 新建医院登记。
func CreateHospital(db *sql.DB, id, name string) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(name) == "" {
		return fmt.Errorf("id 与 name 必填")
	}
	_, err := db.Exec(`INSERT INTO hospitals (id, name) VALUES (?, ?)`, id, name)
	if err != nil {
		return fmt.Errorf("新建医院失败（id 可能已存在）: %w", err)
	}
	return nil
}

// HospitalDataCounts 统计某医院名下的各类数据行数（删除预览/回执用）。
func HospitalDataCounts(db *sql.DB, id string) (map[string]int64, error) {
	counts := map[string]int64{}
	byHospital := []string{"assets", "fact_bundles", "findings", "reports",
		"correlation_reports", "collection_plans", "baselines", "audit_events",
		"exceptions", "role_bindings"}
	for _, t := range byHospital {
		var n int64
		if err := db.QueryRow(`SELECT COUNT(*) FROM "`+t+`" WHERE hospital_id = ?`, id).Scan(&n); err != nil {
			return nil, err
		}
		counts[t] = n
	}
	byBundle := []string{"fact_bundle_evidence"}
	for _, t := range byBundle {
		var n int64
		if err := db.QueryRow(`SELECT COUNT(*) FROM "`+t+`" WHERE bundle_id IN (SELECT id FROM fact_bundles WHERE hospital_id = ?)`, id).Scan(&n); err != nil {
			return nil, err
		}
		counts[t] = n
	}
	byFinding := []string{"reviews", "retests", "remediations"}
	for _, t := range byFinding {
		var n int64
		if err := db.QueryRow(`SELECT COUNT(*) FROM "`+t+`" WHERE finding_id IN (SELECT id FROM findings WHERE hospital_id = ?)`, id).Scan(&n); err != nil {
			return nil, err
		}
		counts[t] = n
	}
	return counts, nil
}

// DeleteHospital 删除一家医院及其全部数据（M28）：单事务按外键
// 子→父序级联删除，返回各表删除行数；医院不存在时报错。
// api_audit_reports 无医院归属列、不在删除范围；rule_toggles 为
// 本站（部署）级配置，亦不动。
func DeleteHospital(db *sql.DB, id string) (map[string]int64, error) {
	var exists int
	if err := db.QueryRow(`SELECT COUNT(*) FROM hospitals WHERE id = ?`, id).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, fmt.Errorf("医院 %s 不存在", id)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	deleted := map[string]int64{}
	steps := []struct{ label, query string }{
		{"reviews", `DELETE FROM reviews WHERE finding_id IN (SELECT id FROM findings WHERE hospital_id = ?)`},
		{"retests", `DELETE FROM retests WHERE finding_id IN (SELECT id FROM findings WHERE hospital_id = ?)`},
		{"remediations", `DELETE FROM remediations WHERE finding_id IN (SELECT id FROM findings WHERE hospital_id = ?)`},
		{"exceptions", `DELETE FROM exceptions WHERE hospital_id = ?`},
		{"findings", `DELETE FROM findings WHERE hospital_id = ?`},
		{"fact_bundle_evidence", `DELETE FROM fact_bundle_evidence WHERE bundle_id IN (SELECT id FROM fact_bundles WHERE hospital_id = ?)`},
		{"fact_bundles", `DELETE FROM fact_bundles WHERE hospital_id = ?`},
		{"reports", `DELETE FROM reports WHERE hospital_id = ?`},
		{"correlation_reports", `DELETE FROM correlation_reports WHERE hospital_id = ?`},
		{"audit_events", `DELETE FROM audit_events WHERE hospital_id = ?`},
		{"collection_plans", `DELETE FROM collection_plans WHERE hospital_id = ?`},
		{"baselines", `DELETE FROM baselines WHERE hospital_id = ?`},
		{"role_bindings", `DELETE FROM role_bindings WHERE hospital_id = ?`},
		{"assets", `DELETE FROM assets WHERE hospital_id = ?`},
		{"hospitals", `DELETE FROM hospitals WHERE id = ?`},
	}
	for _, s := range steps {
		res, err := tx.Exec(s.query, id)
		if err != nil {
			return nil, fmt.Errorf("删除 %s 失败: %w", s.label, err)
		}
		if n, err := res.RowsAffected(); err == nil {
			deleted[s.label] = n
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return deleted, nil
}

// ---- 资产登记（M6） ----

// CreateAsset 正式登记资产（医院须已存在）。
func CreateAsset(db *sql.DB, a Asset) error {
	if strings.TrimSpace(a.ID) == "" || strings.TrimSpace(a.HospitalID) == "" ||
		strings.TrimSpace(a.Kind) == "" || strings.TrimSpace(a.Name) == "" {
		return fmt.Errorf("id/hospital_id/kind/name 必填")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM hospitals WHERE id = ?`, a.HospitalID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("医院 %s 不存在，请先登记医院", a.HospitalID)
	}
	var ep, lb any
	if a.Endpoint != nil {
		ep = *a.Endpoint
	}
	if a.Labels != nil {
		lb = *a.Labels
	}
	_, err := db.Exec(
		`INSERT INTO assets (id, hospital_id, kind, name, endpoint, labels) VALUES (?, ?, ?, ?, ?, ?)`,
		a.ID, a.HospitalID, a.Kind, a.Name, ep, lb)
	if err != nil {
		return fmt.Errorf("登记资产失败（id 可能已存在）: %w", err)
	}
	return nil
}

// UpdateAsset 修正资产的 kind/name/endpoint/labels（主要用于修正导入时自动生成的占位资产）。
func UpdateAsset(db *sql.DB, id, kind, name string, endpoint, labels *string) error {
	if strings.TrimSpace(kind) == "" || strings.TrimSpace(name) == "" {
		return fmt.Errorf("kind 与 name 必填")
	}
	var ep, lb any
	if endpoint != nil {
		ep = *endpoint
	}
	if labels != nil {
		lb = *labels
	}
	res, err := db.Exec(
		`UPDATE assets SET kind = ?, name = ?, endpoint = ?, labels = ? WHERE id = ?`,
		kind, name, ep, lb, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("资产 %s 不存在", id)
	}
	return nil
}

// DeleteAsset 删除资产登记（M17 管理补齐）。只删登记行本身：
// 该资产的历史事实包/问题/报告作为审计证据保留（仍可在事实包页查看），
// 类别页与工作台不再显示该对象。删除不存在的资产返回错误。
func DeleteAsset(db *sql.DB, id string) error {
	res, err := db.Exec(`DELETE FROM assets WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("资产 %s 不存在", id)
	}
	return nil
}
