package platform

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// EvalRun 一次服务端评估的轮次记录（M37-fix3）。
// 轮次号是自增 ID，不再靠时间戳推断：快速连评（间隔 <120 秒）各有独立轮次，
// 空轮次（0 问题）也有行可查，报告汇总才能看到 FAIL 0。
// total/pass/not_applicable 只有新评估才填（评估时已知）；回填的老轮次因问题表
// 不存 PASS/NOT_APPLICABLE 行而留空，fail/unknown/not_run/findings_count 由
// 回填按簇内问题行统计。
type EvalRun struct {
	ID               int64
	BundleID         string
	HospitalID       string
	BaselineMode     string
	BaselinesApplied []string
	Total            sql.NullInt64
	Pass             sql.NullInt64
	Fail             sql.NullInt64
	Unknown          sql.NullInt64
	NotRun           sql.NullInt64
	NotApplicable    sql.NullInt64
	FindingsCount    int
	CreatedAt        string
}

// latestEvalRunID 取某包最新一轮的 ID（无轮次时 ok=false）。
func latestEvalRunID(db *sql.DB, bundleID string) (int64, bool, error) {
	var id sql.NullInt64
	err := db.QueryRow(`SELECT MAX(id) FROM eval_runs WHERE bundle_id = ?`, bundleID).Scan(&id)
	if err != nil {
		return 0, false, err
	}
	if !id.Valid {
		return 0, false, nil
	}
	return id.Int64, true, nil
}

// clusterByGap 按 120 秒间隙把问题行聚成轮次簇（与 fix2-9 的 latestRun 同口径）。
// 仅用于回填老数据与无轮次号行的兜底；新评估一律以 eval_run_id 为准，不走此处。
// 输入按 created_at、id 排序；解析失败的行视作簇边界。
func clusterByGap(rows []FindingRow) [][]FindingRow {
	if len(rows) == 0 {
		return nil
	}
	sorted := make([]FindingRow, len(rows))
	copy(sorted, rows)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].CreatedAt != sorted[j].CreatedAt {
			return sorted[i].CreatedAt < sorted[j].CreatedAt
		}
		return sorted[i].ID < sorted[j].ID
	})
	const layout = "2006-01-02 15:04:05"
	var clusters [][]FindingRow
	start := 0
	for i := 1; i <= len(sorted); i++ {
		boundary := false
		if i == len(sorted) {
			boundary = true
		} else {
			cur, err1 := time.Parse(layout, sorted[i].CreatedAt)
			prev, err2 := time.Parse(layout, sorted[i-1].CreatedAt)
			if err1 != nil || err2 != nil || cur.Sub(prev) > 120*time.Second {
				boundary = true
			}
		}
		if boundary {
			clusters = append(clusters, sorted[start:i])
			start = i
		}
	}
	return clusters
}

// backfillEvalRuns 给 016 之前的问题行补轮次号（Migrate 后调用，幂等）。
// 只处理 eval_run_id IS NULL 的行：按包分组、按 120 秒间隙聚簇，每簇建一行
// eval_runs（baseline_mode='legacy'），再把簇内问题行打上轮次号。聚簇口径与
// fix2-9 的 latestRun 完全一致，故旧数据在新口径下的表现与升级前相同（无回归）；
// 新评估的轮次号由 evaluateCore 直接写入，不再经过聚类。
func backfillEvalRuns(db *sql.DB) error {
	cols, err := db.Query(`PRAGMA table_info(findings)`)
	if err != nil {
		return err
	}
	hasRunCol := false
	for cols.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt sql.NullString
		if err := cols.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			cols.Close()
			return err
		}
		if name == "eval_run_id" {
			hasRunCol = true
		}
	}
	cols.Close()
	if err := cols.Err(); err != nil {
		return err
	}
	if !hasRunCol {
		return nil
	}
	bundles, err := db.Query(`SELECT DISTINCT bundle_id FROM findings WHERE eval_run_id IS NULL`)
	if err != nil {
		return err
	}
	var bundleIDs []string
	for bundles.Next() {
		var b string
		if err := bundles.Scan(&b); err != nil {
			bundles.Close()
			return err
		}
		bundleIDs = append(bundleIDs, b)
	}
	bundles.Close()
	if err := bundles.Err(); err != nil {
		return err
	}
	if len(bundleIDs) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, bundleID := range bundleIDs {
		rows, err := tx.Query(
			`SELECT id, hospital_id, conclusion, strftime('%Y-%m-%d %H:%M:%S', created_at)
			 FROM findings WHERE bundle_id = ? AND eval_run_id IS NULL ORDER BY created_at, id`, bundleID)
		if err != nil {
			return err
		}
		var frs []FindingRow
		hospitalID := ""
		for rows.Next() {
			var f FindingRow
			var hosp string
			if err := rows.Scan(&f.ID, &hosp, &f.Conclusion, &f.CreatedAt); err != nil {
				rows.Close()
				return err
			}
			hospitalID = hosp
			frs = append(frs, f)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, cluster := range clusterByGap(frs) {
			if len(cluster) == 0 {
				continue
			}
			var fail, unknown, notRun int
			for _, f := range cluster {
				switch f.Conclusion {
				case "FAIL":
					fail++
				case "UNKNOWN":
					unknown++
				case "NOT_RUN":
					notRun++
				}
			}
			res, err := tx.Exec(
				`INSERT INTO eval_runs (bundle_id, hospital_id, baseline_mode, baselines_applied,
					fail, unknown, not_run, findings_count, created_at)
				 VALUES (?, ?, 'legacy', '[]', ?, ?, ?, ?, ?)`,
				bundleID, hospitalID, fail, unknown, notRun, len(cluster),
				cluster[len(cluster)-1].CreatedAt)
			if err != nil {
				return fmt.Errorf("回填轮次 %s: %w", bundleID, err)
			}
			runID, err := res.LastInsertId()
			if err != nil {
				return err
			}
			var ids []string
			var args []any
			for _, f := range cluster {
				ids = append(ids, "?")
				args = append(args, f.ID)
			}
			args = append([]any{runID}, args...)
			if _, err := tx.Exec(
				`UPDATE findings SET eval_run_id = ? WHERE id IN (`+strings.Join(ids, ",")+`)`, args...); err != nil {
				return fmt.Errorf("回填问题行轮次号 %s: %w", bundleID, err)
			}
		}
	}
	return tx.Commit()
}

// findingsOfRun 取某轮次的问题行（runID<=0 时返回空）。
func findingsOfRun(findings []FindingRow, runID int64) []FindingRow {
	if runID <= 0 {
		return []FindingRow{}
	}
	out := []FindingRow{}
	for _, f := range findings {
		if f.EvalRunID == runID {
			out = append(out, f)
		}
	}
	return out
}

// latestRunFindingsByRun 取问题行中的最新一轮：优先轮次号（新评估），
// 无轮次号时回退 120 秒聚类（老快照、老数据兜底）。
func latestRunFindingsByRun(findings []FindingRow) []FindingRow {
	var maxRun int64
	for _, f := range findings {
		if f.EvalRunID > maxRun {
			maxRun = f.EvalRunID
		}
	}
	if maxRun > 0 {
		return findingsOfRun(findings, maxRun)
	}
	clusters := clusterByGap(findings)
	if len(clusters) == 0 {
		return findings
	}
	return clusters[len(clusters)-1]
}

// nullInt64 构造有效的 NullInt64。
func nullInt64(v int) sql.NullInt64 {
	return sql.NullInt64{Int64: int64(v), Valid: true}
}

// encodeStringSlice 编码字符串切片为 JSON（空切片编为 [] 而非 null）。
func encodeStringSlice(s []string) string {
	if s == nil {
		s = []string{}
	}
	b, _ := json.Marshal(s)
	return string(b)
}
