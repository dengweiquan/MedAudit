package platform

import (
	"database/sql"
	"fmt"
)

// wipeTables 一键清场要清空的数据表，按外键子表→父表排序（库启用了
// FK 约束，顺序错会整事务回滚）：reviews/retests/remediations 引用
// findings；fact_bundles 引用 collection_plans；assets/reports/
// role_bindings/collection_plans 引用 hospitals。
// schema_migrations 是结构账本，不在此列；auth_users 单独处理
// （清空后重播默认管理员）。
var wipeTables = []string{
	"reviews", "retests", "remediations", "exceptions", "findings",
	"fact_bundle_evidence", "fact_bundles", "collection_plans",
	"assets", "reports", "api_audit_reports", "correlation_reports",
	"baselines", "rule_toggles", "audit_events", "alerts", "role_bindings",
	"hospitals", "users", "rules",
}

// WipeAllData 清空全部业务数据（新客户现场交接用，M27）：单事务删除
// 所有数据表行，用户表清空后重播默认管理员（admin / 默认口令，首登
// 强制改密）。返回各表删除行数。调用方负责：清场前备份、清场后吊销
// 全部会话、按本站配置重登记本站医院。
func WipeAllData(db *sql.DB) (map[string]int64, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	deleted := map[string]int64{}
	for _, t := range wipeTables {
		res, err := tx.Exec(`DELETE FROM "` + t + `"`)
		if err != nil {
			return nil, fmt.Errorf("清空 %s 失败: %w", t, err)
		}
		if n, err := res.RowsAffected(); err == nil {
			deleted[t] = n
		}
	}
	res, err := tx.Exec(`DELETE FROM auth_users`)
	if err != nil {
		return nil, fmt.Errorf("清空用户失败: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil {
		deleted["auth_users"] = n
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	// 用户表已空，恢复出厂管理员。
	if err := SeedDefaultAdmin(db); err != nil {
		return deleted, fmt.Errorf("重播默认管理员失败: %w", err)
	}
	return deleted, nil
}
