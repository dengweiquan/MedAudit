package platform

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"medaudit/internal/facts"
)

// BundleDetail 事实包详情（M16）：元数据 + 执行状态 + 收据明细 + 事实计数。
// FactsPage 只给事实分页，收据（PARTIAL 缺口定位）此前无端点可读，这里补齐。
type BundleDetail struct {
	ID               string          `json:"id"`
	HospitalID       string          `json:"hospital_id"`
	PlanID           string          `json:"plan_id"`
	AssetID          string          `json:"asset_id"`
	Adapter          string          `json:"adapter"`
	Execution        string          `json:"execution"`
	ImportedAt       string          `json:"imported_at"`
	CollectorVersion string          `json:"collector_version,omitempty"`
	FactCount        int             `json:"fact_count"`
	CountsByKind     map[string]int  `json:"counts_by_kind"`
	Receipts         []facts.Receipt `json:"receipts"`
}

func BundleDetailByID(db *sql.DB, id string) (*BundleDetail, error) {
	var d BundleDetail
	var raw string
	err := db.QueryRow(`SELECT hospital_id, plan_id, asset_id, adapter, execution, imported_at, bundle FROM fact_bundles WHERE id = ?`, id).
		Scan(&d.HospitalID, &d.PlanID, &d.AssetID, &d.Adapter, &d.Execution, &d.ImportedAt, &raw)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("事实包 %s 不存在", id)
	}
	if err != nil {
		return nil, err
	}
	d.ID = id
	var b facts.FactBundle
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return nil, fmt.Errorf("事实包解析失败: %w", err)
	}
	d.CollectorVersion = b.Collector.Version
	d.FactCount = len(b.Facts)
	d.CountsByKind = map[string]int{}
	for _, f := range b.Facts {
		d.CountsByKind[string(f.Kind)]++
	}
	d.Receipts = b.Receipts
	if d.Receipts == nil {
		d.Receipts = []facts.Receipt{}
	}
	return &d, nil
}

// BackupSnapshot 用 VACUUM INTO 生成平台库的一致性快照文件（M16），
// 返回文件路径，调用方负责发送后删除。
func BackupSnapshot(db *sql.DB, dir string) (string, error) {
	f, err := os.CreateTemp(dir, "medaudit-backup-*.db")
	if err != nil {
		return "", err
	}
	path := f.Name()
	_ = f.Close()
	_ = os.Remove(path) // VACUUM INTO 要求目标文件不存在
	if _, err := db.Exec("VACUUM INTO '" + strings.ReplaceAll(path, "'", "''") + "'"); err != nil {
		return "", fmt.Errorf("生成快照失败: %w", err)
	}
	return path, nil
}
