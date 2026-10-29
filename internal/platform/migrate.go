package platform

import (
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"
)

// SQLite 版迁移（唯一迁移来源；早期 MySQL 版已于 M37-3.3 清理）。
//
//go:embed sqlite_migrations/*.sql
var sqliteMigrations embed.FS

// Migrate 按文件名顺序应用尚未执行的迁移，幂等。
// 已应用版本记录在 schema_migrations（与 MySQL 版同名同义）。
func Migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT NOT NULL PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("创建 schema_migrations: %w", err)
	}
	entries, err := sqliteMigrations.ReadDir("sqlite_migrations")
	if err != nil {
		return fmt.Errorf("读取内嵌迁移: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		version := strings.TrimSuffix(name, ".sql")
		var n int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version,
		).Scan(&n); err != nil {
			return fmt.Errorf("检查迁移 %s: %w", version, err)
		}
		if n > 0 {
			continue
		}
		body, err := sqliteMigrations.ReadFile("sqlite_migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("应用迁移 %s: %w", version, err)
		}
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO schema_migrations (version) VALUES (?)`, version,
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("记录迁移 %s: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("提交迁移 %s: %w", version, err)
		}
	}
	// M37-fix3：给 016 之前的问题行补轮次号（幂等；无待回填行时为空操作）。
	// 放 Go 里而非 SQL 迁移：间隙聚类是过程逻辑，SQL 窗口函数写法难审；
	// 聚簇口径与 fix2-9 的 latestRun 完全一致，旧数据行为不变。
	if err := backfillEvalRuns(db); err != nil {
		return fmt.Errorf("回填评估轮次: %w", err)
	}
	return nil
}
