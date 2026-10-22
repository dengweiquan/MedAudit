// Package dbutil 提供数据库适配器共享的采集基础设施：
// 带行数/字节上限的查询、连接与查询双层超时、权限不足错误分类。
// 所有查询均为只读；模板 SQL 由各适配器在 queries/ 下版本化管理。
package dbutil

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const (
	// DefaultRowLimit 单模板默认行数上限，超限标 truncated。
	DefaultRowLimit = 5000
	// DefaultByteLimit 单模板默认字节上限（近似），超限标 truncated。
	DefaultByteLimit = 10 << 20 // 10MB
	// DefaultQueryTimeout 单模板默认查询超时。
	DefaultQueryTimeout = 30 * time.Second
)

// Rows 查询结果：列名与字符串化行。
type Rows struct {
	Columns   []string
	Data      [][]string
	Truncated bool
}

// QueryRows 执行只读查询，返回字符串化结果。
// 超过 rowLimit 行或 byteLimit 字节时停止并置 Truncated。
// 调用方负责传入版本化模板 SQL；此处不做任何 SQL 改写。
func QueryRows(ctx context.Context, db *sql.DB, query string, queryTimeout time.Duration, rowLimit int, byteLimit int64) (*Rows, error) {
	if queryTimeout <= 0 {
		queryTimeout = DefaultQueryTimeout
	}
	if rowLimit <= 0 {
		rowLimit = DefaultRowLimit
	}
	if byteLimit <= 0 {
		byteLimit = DefaultByteLimit
	}
	qctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	rows, err := db.QueryContext(qctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	r := &Rows{Columns: cols}
	var totalBytes int64
	// 多读一行用于判定截断。
	for len(r.Data) <= rowLimit {
		if !rows.Next() {
			break
		}
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		rec := make([]string, len(cols))
		for i, v := range vals {
			s := stringify(v)
			rec[i] = s
			totalBytes += int64(len(s))
		}
		r.Data = append(r.Data, rec)
		if totalBytes > byteLimit {
			r.Truncated = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(r.Data) > rowLimit {
		r.Data = r.Data[:rowLimit]
		r.Truncated = true
	}
	return r, nil
}

func stringify(v interface{}) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case []byte:
		return string(t)
	case string:
		return t
	case time.Time:
		return t.UTC().Format(time.RFC3339)
	default:
		return fmt.Sprintf("%v", t)
	}
}

// ColIndex 返回列名在结果中的下标，不存在返回 -1。
func (r *Rows) ColIndex(name string) int {
	for i, c := range r.Columns {
		if strings.EqualFold(c, name) {
			return i
		}
	}
	return -1
}

// IsPermissionDenied 判断错误是否为"权限不足/对象不可见"类。
// 覆盖三类驱动的典型错误码；未知错误返回 false 由调用方按失败处理。
func IsPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToUpper(err.Error())
	// MySQL: 1142/1143 SELECT command denied, 1044 access denied for database.
	if strings.Contains(msg, "ERROR 1142") || strings.Contains(msg, "ERROR 1143") ||
		strings.Contains(msg, "ERROR 1044") || strings.Contains(msg, "SELECT COMMAND DENIED") {
		return true
	}
	// SQL Server: 229/230 permission denied.
	if strings.Contains(msg, "229") && strings.Contains(msg, "DENIED") ||
		strings.Contains(msg, "230") && strings.Contains(msg, "DENIED") {
		return true
	}
	// Oracle: ORA-00942（无权时常见为"表或视图不存在"）、ORA-01031 权限不足。
	if strings.Contains(msg, "ORA-00942") || strings.Contains(msg, "ORA-01031") {
		return true
	}
	// PostgreSQL: 42501 insufficient_privilege（lib/pq 文本为"permission denied for ..."）。
	if strings.Contains(msg, "42501") || strings.Contains(msg, "PERMISSION DENIED") {
		return true
	}
	return false
}

// IsTimeout 判断是否为超时类错误。
func IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "timed out")
}
