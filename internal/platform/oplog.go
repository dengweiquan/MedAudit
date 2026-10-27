package platform

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OpEntry 平台操作日志一行。
type OpEntry struct {
	ID       int64  `json:"id"`
	At       string `json:"at"` // UTC RFC3339
	Actor    string `json:"actor"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Status   int    `json:"status"`
	ClientIP string `json:"client_ip"`
	Note     string `json:"note"`
	PrevHash string `json:"-"`
	Hash     string `json:"-"`
}

// opLogMu 串行化追加，保证哈希链按 id 顺序连续。
var opLogMu sync.Mutex

func opHash(e OpEntry) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		e.PrevHash, e.At, e.Actor, e.Method, e.Path,
		strconv.Itoa(e.Status), e.ClientIP, e.Note,
	}, "\x1f")))
	return hex.EncodeToString(sum[:])
}

// AppendOpLog 追加一条操作日志（At 为空时取当前 UTC 时间）。
func AppendOpLog(db *sql.DB, e OpEntry) error {
	opLogMu.Lock()
	defer opLogMu.Unlock()
	if e.At == "" {
		e.At = time.Now().UTC().Format(time.RFC3339)
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	err = tx.QueryRow(`SELECT hash FROM op_log ORDER BY id DESC LIMIT 1`).Scan(&e.PrevHash)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	e.Hash = opHash(e)
	if _, err := tx.Exec(`INSERT INTO op_log (at, actor, method, path, status, client_ip, note, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.At, e.Actor, e.Method, e.Path, e.Status, e.ClientIP, e.Note, e.PrevHash, e.Hash); err != nil {
		return err
	}
	return tx.Commit()
}

// ListOpLog 按时间倒序分页列出操作日志。
func ListOpLog(db *sql.DB, offset, limit int) ([]OpEntry, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM op_log`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.Query(`SELECT id, at, actor, method, path, status, client_ip, note
		FROM op_log ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []OpEntry{}
	for rows.Next() {
		var e OpEntry
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Method, &e.Path, &e.Status, &e.ClientIP, &e.Note); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// VerifyOpLog 逐行复算哈希链。ok=false 时 brokenAt 为第一处断链的行 id。
func VerifyOpLog(db *sql.DB) (ok bool, rowsChecked int, brokenAt int64, err error) {
	rows, err := db.Query(`SELECT id, at, actor, method, path, status, client_ip, note, prev_hash, hash
		FROM op_log ORDER BY id`)
	if err != nil {
		return false, 0, 0, err
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		var e OpEntry
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Method, &e.Path, &e.Status, &e.ClientIP, &e.Note, &e.PrevHash, &e.Hash); err != nil {
			return false, rowsChecked, 0, err
		}
		rowsChecked++
		if e.PrevHash != prev || opHash(e) != e.Hash {
			return false, rowsChecked, e.ID, nil
		}
		prev = e.Hash
	}
	if err := rows.Err(); err != nil {
		return false, rowsChecked, 0, fmt.Errorf("读取操作日志: %w", err)
	}
	return true, rowsChecked, 0, nil
}
