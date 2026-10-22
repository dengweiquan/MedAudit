package platform

import (
	"database/sql"
)

// ensureParents 确保 bundle 引用的 hospital/plan/asset 存在；
// 缺失时创建 auto_created 桩行（M1 闭环引导，M2 资产登记 UI 接管后收紧）。
func ensureParents(db *sql.DB, hospitalID, planID, assetID string) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM hospitals WHERE id = ?`, hospitalID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := db.Exec(`INSERT INTO hospitals (id, name) VALUES (?, ?)`,
			hospitalID, "auto-created:"+hospitalID); err != nil {
			return err
		}
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM collection_plans WHERE id = ?`, planID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := db.Exec(
			`INSERT INTO collection_plans (id, hospital_id, name, profile, spec, created_by)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			planID, hospitalID, "auto-created:"+planID, "m1-bootstrap",
			`{"auto_created":true}`, "collector-import"); err != nil {
			return err
		}
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM assets WHERE id = ?`, assetID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := db.Exec(
			`INSERT INTO assets (id, hospital_id, kind, name) VALUES (?, ?, ?, ?)`,
			assetID, hospitalID, "unknown", "auto-created:"+assetID); err != nil {
			return err
		}
	}
	return nil
}
