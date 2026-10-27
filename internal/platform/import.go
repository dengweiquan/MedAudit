package platform

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"

	"medaudit/internal/facts"
)

// ErrDuplicateBundle 事实包已导入过（幂等，不重复计数）。
var ErrDuplicateBundle = errors.New("bundle 已导入")

// BundleSummary 事实包摘要（列表用）。
type BundleSummary struct {
	ID            string `json:"id"`
	PlanID        string `json:"plan_id"`
	HospitalID    string `json:"hospital_id"`
	AssetID       string `json:"asset_id"`
	SchemaVersion string `json:"schema_version"`
	Adapter       string `json:"adapter"`
	Execution     string `json:"execution"`
	FactCount     int    `json:"fact_count"`
	ReceiptCount  int    `json:"receipt_count"`
	ImportedAt    string `json:"imported_at"`
}

// ImportBundle 导入事实包：校验 → 去重 → 落库。重复导入返回 ErrDuplicateBundle。
// rawZip 非空且密钥环可用时，原始证据在同一事务内加密落库（M4-3b）。
func ImportBundle(db *sql.DB, b *facts.FactBundle, rawZip []byte, kr *EvidenceKeyring) error {
	if errs := b.Validate(); len(errs) != 0 {
		return errors.New("事实包校验失败")
	}
	if err := ensureParents(db, b.Scope.HospitalID, b.PlanID, b.Scope.AssetID); err != nil {
		return err
	}
	var exists int
	err := db.QueryRow(`SELECT COUNT(*) FROM fact_bundles WHERE id = ?`, b.BundleID).Scan(&exists)
	if err != nil {
		return err
	}
	if exists > 0 {
		return ErrDuplicateBundle
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`INSERT INTO fact_bundles (id, plan_id, hospital_id, asset_id, schema_version, adapter, execution, bundle)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		b.BundleID, b.PlanID, b.Scope.HospitalID, b.Scope.AssetID,
		b.SchemaVersion, string(b.Collector.Adapter), string(b.Execution), string(raw),
	); err != nil {
		return err
	}
	// 原始证据加密落库（M4-3b）：未配置密钥环时跳过，行为同旧版。
	if kr != nil && len(rawZip) > 0 {
		if err := StoreEvidence(tx, kr, b.BundleID, rawZip); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// 权限漂移告警：失败只记日志，不影响导入。
	if _, err := RecordDriftAlert(db, b.BundleID); err != nil {
		log.Printf("[alert] %s 漂移比对失败: %v", b.BundleID, err)
	}
	return nil
}

// ListBundles 列出已导入的事实包摘要。
func ListBundles(db *sql.DB) ([]BundleSummary, error) {
	rows, err := db.Query(
		`SELECT id, plan_id, hospital_id, asset_id, schema_version, adapter, execution,
		        json_array_length(bundle, '$.facts'), json_array_length(bundle, '$.receipts'),
		        strftime('%Y-%m-%d %H:%M:%S', imported_at)
		 FROM fact_bundles ORDER BY imported_at DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BundleSummary
	for rows.Next() {
		var s BundleSummary
		if err := rows.Scan(&s.ID, &s.PlanID, &s.HospitalID, &s.AssetID,
			&s.SchemaVersion, &s.Adapter, &s.Execution,
			&s.FactCount, &s.ReceiptCount, &s.ImportedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []BundleSummary{}
	}
	return out, nil
}

// ListBundlesByAsset 返回某对象的全部事实包摘要（无 LIMIT，不受 ListBundles
// 的 100 条上限影响；M37-fix-3）。返回结构与 ListBundles 相同，按导入时间倒序。
func ListBundlesByAsset(db *sql.DB, assetID string) ([]BundleSummary, error) {
	rows, err := db.Query(
		`SELECT id, plan_id, hospital_id, asset_id, schema_version, adapter, execution,
		        json_array_length(bundle, '$.facts'), json_array_length(bundle, '$.receipts'),
		        strftime('%Y-%m-%d %H:%M:%S', imported_at)
		 FROM fact_bundles WHERE asset_id = ? ORDER BY imported_at DESC, id DESC`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BundleSummary
	for rows.Next() {
		var s BundleSummary
		if err := rows.Scan(&s.ID, &s.PlanID, &s.HospitalID, &s.AssetID,
			&s.SchemaVersion, &s.Adapter, &s.Execution,
			&s.FactCount, &s.ReceiptCount, &s.ImportedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []BundleSummary{}
	}
	return out, nil
}

// LatestBundles 返回每个资产最新导入的事实包摘要。
// ListBundles 有 LIMIT 100，对象一多，老对象的最近审计会从列表消失；
// 工作台的「最近审计」须用本函数计算，不受 100 条上限影响（M37-1.2）。
func LatestBundles(db *sql.DB) ([]BundleSummary, error) {
	rows, err := db.Query(
		`SELECT id, plan_id, hospital_id, asset_id, schema_version, adapter, execution,
		        json_array_length(bundle, '$.facts'), json_array_length(bundle, '$.receipts'),
		        strftime('%Y-%m-%d %H:%M:%S', imported_at)
		 FROM fact_bundles ORDER BY asset_id, imported_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BundleSummary
	seen := map[string]bool{}
	for rows.Next() {
		var s BundleSummary
		if err := rows.Scan(&s.ID, &s.PlanID, &s.HospitalID, &s.AssetID,
			&s.SchemaVersion, &s.Adapter, &s.Execution,
			&s.FactCount, &s.ReceiptCount, &s.ImportedAt); err != nil {
			return nil, err
		}
		if seen[s.AssetID] {
			continue
		}
		seen[s.AssetID] = true
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []BundleSummary{}
	}
	return out, nil
}
