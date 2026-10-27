package platform

import (
	"database/sql"
	"math"
	"os"
	"sort"
	"strconv"
	"time"
)

// 复检周期提醒：按对象最近一次导入事实包的时间判断是否到期。开启了定期
// 自动复检的对象由调度器执行（见 schedule.go），其余由工程师「开始审计」
// 或 ma audit 复检。

// DefaultAuditCycleDays 默认复检周期（天），可由 MEDAUDIT_AUDIT_CYCLE_DAYS 覆盖。
const DefaultAuditCycleDays = 30

// AuditCycleDays 读取复检周期配置；非法或未设置时取默认值。
func AuditCycleDays() int {
	if n, err := strconv.Atoi(os.Getenv("MEDAUDIT_AUDIT_CYCLE_DAYS")); err == nil && n > 0 {
		return n
	}
	return DefaultAuditCycleDays
}

// AuditDue 单个对象的复检状态。
type AuditDue struct {
	AssetID     string `json:"asset_id"`
	HospitalID  string `json:"hospital_id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	LastAuditAt string `json:"last_audit_at"` // UTC，空表示从未审计
	DueAt       string `json:"due_at"`        // UTC，从未审计时为空
	DaysLeft    int    `json:"days_left"`     // 距到期天数，负数为已逾期天数
	Status      string `json:"status"`        // never | overdue | due_soon | ok
	Auto        bool   `json:"auto"`          // 已开启定期自动复检
}

// ListAuditDue 列出全部已分类对象的复检状态，需处理的排在前面。
// 7 天内到期记为 due_soon。
func ListAuditDue(db *sql.DB, cycleDays int, now time.Time) ([]AuditDue, error) {
	rows, err := db.Query(`SELECT a.id, a.hospital_id, a.name, a.kind,
		       COALESCE((SELECT MAX(b.imported_at) FROM fact_bundles b WHERE b.asset_id = a.id), ''),
		       EXISTS (SELECT 1 FROM audit_schedules s WHERE s.asset_id = a.id)
		  FROM assets a WHERE a.kind <> 'unknown'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditDue{}
	for rows.Next() {
		var d AuditDue
		var last string
		if err := rows.Scan(&d.AssetID, &d.HospitalID, &d.Name, &d.Kind, &last, &d.Auto); err != nil {
			return nil, err
		}
		if t, ok := parseStoredTime(last); ok {
			due := t.Add(time.Duration(cycleDays) * 24 * time.Hour)
			d.LastAuditAt = t.UTC().Format(time.RFC3339)
			d.DueAt = due.UTC().Format(time.RFC3339)
			d.DaysLeft = int(math.Floor(due.Sub(now).Hours() / 24))
			if due.Before(now) {
				d.Status = "overdue"
			} else if d.DaysLeft < 7 {
				d.Status = "due_soon"
			} else {
				d.Status = "ok"
			}
		} else {
			d.Status = "never"
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rank := map[string]int{"overdue": 0, "never": 1, "due_soon": 2, "ok": 3}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if rank[a.Status] != rank[b.Status] {
			return rank[a.Status] < rank[b.Status]
		}
		if a.DaysLeft != b.DaysLeft {
			return a.DaysLeft < b.DaysLeft
		}
		return a.AssetID < b.AssetID
	})
	return out, nil
}
