package platform

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"medaudit/internal/facts"
)

// FactsPage 事实明细分页结果（M6：主机/数据库明细浏览的数据来源）。
type FactsPage struct {
	BundleID     string         `json:"bundle_id"`
	Total        int            `json:"total"`
	CountsByKind map[string]int `json:"counts_by_kind"`
	Facts        []facts.Fact   `json:"facts"`
}

// BundleFacts 读取已存事实包并按 kind 过滤、分页返回事实明细。
// limit<=0 取 200，上限 1000；offset<0 取 0。
func BundleFacts(db *sql.DB, bundleID, kind string, offset, limit int) (*FactsPage, error) {
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
		return nil, fmt.Errorf("事实包解析失败: %w", err)
	}
	counts := map[string]int{}
	filtered := make([]facts.Fact, 0, len(b.Facts))
	for _, f := range b.Facts {
		counts[string(f.Kind)]++
		if kind == "" || string(f.Kind) == kind {
			filtered = append(filtered, f)
		}
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	page := []facts.Fact{}
	if offset < len(filtered) {
		end := offset + limit
		if end > len(filtered) {
			end = len(filtered)
		}
		page = filtered[offset:end]
	}
	return &FactsPage{
		BundleID:     bundleID,
		Total:        len(filtered),
		CountsByKind: counts,
		Facts:        page,
	}, nil
}
