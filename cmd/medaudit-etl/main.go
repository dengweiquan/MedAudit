// medaudit-etl：一次性迁移工具（M5）——把平台数据从 MySQL 全量迁入 SQLite。
//
// 用法：
//   ETL_MYSQL_DSN='user:pass@tcp(127.0.0.1:13306)/medaudit' \
//     medaudit-etl --out /path/to/medaudit.db
//
// 行为：先在目标文件上执行内嵌 SQLite 迁移建空库，再逐表复制
// （schema_migrations 除外，由迁移执行器自理）；逐表行数对账，
// 最后跑 integrity_check 与 foreign_key_check。任一不符即非零退出。
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "modernc.org/sqlite"

	"medaudit/internal/platform"
)

// 复制顺序按外键依赖从父到子（加载时另关外键检查，顺序只为可读）。
var tables = []string{
	"hospitals", "users", "role_bindings", "assets", "collection_plans",
	"fact_bundles", "rules", "findings", "reports", "audit_events",
	"reviews", "exceptions", "remediations", "retests", "baselines",
	"fact_bundle_evidence", "api_audit_reports",
}

func main() {
	out := flag.String("out", "", "目标 SQLite 文件路径")
	flag.Parse()
	dsn := os.Getenv("ETL_MYSQL_DSN")
	if dsn == "" || *out == "" {
		fmt.Println("需要 ETL_MYSQL_DSN 与 --out")
		os.Exit(2)
	}
	if _, err := os.Stat(*out); err == nil {
		fmt.Println("目标文件已存在，拒绝覆盖:", *out)
		os.Exit(2)
	}

	// 1) 建空库（跑内嵌迁移）
	seed, err := platform.Open(*out)
	if err != nil {
		fatal("打开目标库", err)
	}
	if err := platform.Migrate(seed); err != nil {
		fatal("目标库迁移", err)
	}
	seed.Close()

	// 2) 以外键关闭模式打开目标库做批量加载
	dst, err := sql.Open("sqlite", "file:"+*out+
		"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(0)&_pragma=busy_timeout(10000)")
	if err != nil {
		fatal("打开目标库(加载)", err)
	}
	defer dst.Close()
	dst.SetMaxOpenConns(1)

	src, err := sql.Open("mysql", dsn)
	if err != nil {
		fatal("打开源库", err)
	}
	defer src.Close()
	if err := src.Ping(); err != nil {
		fatal("源库 Ping", err)
	}

	totalSrc, totalDst := 0, 0
	for _, t := range tables {
		n, err := copyTable(src, dst, t)
		if err != nil {
			fatal("复制 "+t, err)
		}
		var want int
		if err := src.QueryRow("SELECT COUNT(*) FROM `"+t+"`").Scan(&want); err != nil {
			fatal("源计数 "+t, err)
		}
		if want != n {
			fmt.Printf("%-24s 源 %d / 目标 %d —— 不一致！\n", t, want, n)
			os.Exit(1)
		}
		fmt.Printf("%-24s %d 行 OK\n", t, n)
		totalSrc += want
		totalDst += n
	}
	fmt.Printf("合计：源 %d 行 / 目标 %d 行\n", totalSrc, totalDst)

	// 3) 完整性校验（新连接开外键）
	chk, err := platform.Open(*out)
	if err != nil {
		fatal("重开目标库", err)
	}
	defer chk.Close()
	var ic string
	if err := chk.QueryRow(`PRAGMA integrity_check`).Scan(&ic); err != nil {
		fatal("integrity_check", err)
	}
	fmt.Println("integrity_check:", ic)
	if ic != "ok" {
		os.Exit(1)
	}
	rows, err := chk.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		fatal("foreign_key_check", err)
	}
	defer rows.Close()
	fkBad := 0
	for rows.Next() {
		fkBad++
	}
	if fkBad > 0 {
		fmt.Println("foreign_key_check 违规行数:", fkBad)
		os.Exit(1)
	}
	fmt.Println("foreign_key_check: ok")
	fmt.Println("ETL 完成:", *out)
}

func copyTable(src, dst *sql.DB, table string) (int, error) {
	// 目标列与类型（以 SQLite 结构为准）
	trows, err := dst.Query("PRAGMA table_info(`" + table + "`)")
	if err != nil {
		return 0, err
	}
	var cols []string
	blobCol := map[string]bool{}
	for trows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := trows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			trows.Close()
			return 0, err
		}
		cols = append(cols, name)
		if strings.Contains(strings.ToUpper(ctype), "BLOB") {
			blobCol[name] = true
		}
	}
	trows.Close()
	if len(cols) == 0 {
		return 0, fmt.Errorf("目标表 %s 不存在", table)
	}

	colList := "`" + strings.Join(cols, "`,`") + "`"
	rows, err := src.Query("SELECT " + colList + " FROM `" + table + "`")
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	ph := strings.TrimSuffix(strings.Repeat("?,", len(cols)), ",")
	tx, err := dst.Begin()
	if err != nil {
		return 0, err
	}
	stmt, err := tx.Prepare("INSERT INTO `" + table + "` (" + colList + ") VALUES (" + ph + ")")
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	defer stmt.Close()

	n := 0
	for rows.Next() {
		holders := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range holders {
			ptrs[i] = &holders[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			tx.Rollback()
			return 0, err
		}
		vals := make([]any, len(cols))
		for i, h := range holders {
			vals[i] = convert(h, blobCol[cols[i]])
		}
		if _, err := stmt.Exec(vals...); err != nil {
			tx.Rollback()
			return 0, fmt.Errorf("第 %d 行插入: %w", n+1, err)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		tx.Rollback()
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// convert 把 MySQL 驱动返回值转成 SQLite 友好的类型：
// 文本列的 []byte 转 string；时间转 UTC 文本（与 MySQL TIMESTAMP 显示格式一致）。
func convert(v any, blob bool) any {
	switch x := v.(type) {
	case nil:
		return nil
	case []byte:
		if blob {
			return x
		}
		return string(x)
	case time.Time:
		return x.UTC().Format("2006-01-02 15:04:05")
	case bool:
		if x {
			return int64(1)
		}
		return int64(0)
	default:
		return v
	}
}

func fatal(step string, err error) {
	fmt.Println("ETL 失败于", step+":", err)
	os.Exit(1)
}
