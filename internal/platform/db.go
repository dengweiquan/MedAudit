// Package platform 提供平台自身的数据访问（本地 SQLite 文件，
// 与被核查数据库完全分离）。
package platform

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Open 打开（不存在则创建）平台 SQLite 数据库文件。
// WAL 模式提升并发读写；busy_timeout 兜底锁等待；单连接串行化写入，
// 避免多连接并发写时的 SQLITE_BUSY。
func Open(path string) (*sql.DB, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("创建数据目录 %s: %w", dir, err)
		}
	}
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// Asset 平台登记的资产行。
type Asset struct {
	ID         string  `json:"id"`
	HospitalID string  `json:"hospital_id"`
	Kind       string  `json:"kind"`
	Name       string  `json:"name"`
	Endpoint   *string `json:"endpoint"`
	Labels     *string `json:"labels"`
}

// ListAssets 列出全部资产（M0：最小列表）。
func ListAssets(db *sql.DB) ([]Asset, error) {
	rows, err := db.Query(`SELECT id, hospital_id, kind, name, endpoint, labels FROM assets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		var a Asset
		var ep, lb sql.NullString
		if err := rows.Scan(&a.ID, &a.HospitalID, &a.Kind, &a.Name, &ep, &lb); err != nil {
			return nil, err
		}
		if ep.Valid {
			a.Endpoint = &ep.String
		}
		if lb.Valid {
			a.Labels = &lb.String
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []Asset{}
	}
	return out, nil
}
