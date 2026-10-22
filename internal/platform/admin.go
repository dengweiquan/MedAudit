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
