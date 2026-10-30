package platform

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
)

// M37-fix3：最新一轮以轮次号为准，不再靠时间戳聚类。
// 两轮问题行在时间上交错（快速连评）时，只取轮次号最大的那轮。
func TestLatestRunPrefersRunID(t *testing.T) {
	rows := []FindingRow{
		{ID: 1, RuleID: "r1", Conclusion: "FAIL", CreatedAt: "2026-10-20 10:00:00", EvalRunID: 1},
		{ID: 2, RuleID: "r2", Conclusion: "FAIL", CreatedAt: "2026-10-20 10:00:30", EvalRunID: 2},
		{ID: 3, RuleID: "r3", Conclusion: "FAIL", CreatedAt: "2026-10-20 10:00:40", EvalRunID: 1},
		{ID: 4, RuleID: "r4", Conclusion: "FAIL", CreatedAt: "2026-10-20 10:00:50", EvalRunID: 2},
	}
	got := latestRun(rows)
	if len(got) != 2 || got[0].ID != 2 || got[1].ID != 4 {
		t.Fatalf("按轮次号取最新一轮应为 run 2 的两行，实际 %+v", got)
	}
}

// M37-fix3：无轮次号的行（老快照、老数据）回退 120 秒聚类，与 fix2-9 同口径。
func TestLatestRunFallbackClustering(t *testing.T) {
	rows := []FindingRow{
		{ID: 1, RuleID: "r1", Conclusion: "FAIL", CreatedAt: "2026-10-20 10:00:00"},
		{ID: 2, RuleID: "r2", Conclusion: "FAIL", CreatedAt: "2026-10-20 10:00:30"},
		{ID: 3, RuleID: "r3", Conclusion: "FAIL", CreatedAt: "2026-10-20 10:05:00"},
	}
	got := latestRun(rows)
	if len(got) != 1 || got[0].ID != 3 {
		t.Fatalf("无轮次号时应回退聚类取最后一簇（1 行），实际 %+v", got)
	}
}

func openTestDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func seedBundle(t *testing.T, db *sql.DB) {
	t.Helper()
	if err := CreateHospital(db, "h-test", "测试医院"); err != nil {
		t.Fatal(err)
	}
	if err := CreateAsset(db, Asset{ID: "a-mysql", HospitalID: "h-test", Kind: "db-mysql", Name: "测试 MySQL"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO collection_plans (id, hospital_id, name, profile, spec, created_by)
		VALUES ('p1', 'h-test', 'P1', 'prof', '{}', 'web')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO fact_bundles (id, plan_id, hospital_id, asset_id, schema_version, adapter, execution, bundle, imported_at)
		VALUES ('bundle-1', 'p1', 'h-test', 'a-mysql', '1', 'db-mysql', 'COMPLETE', '{"facts":[],"receipts":[]}', '2026-10-20 10:00:00')`); err != nil {
		t.Fatal(err)
	}
}

// M37-fix3：回填把老问题行按 120 秒聚类分组建轮次，行为与升级前一致；幂等。
func TestBackfillEvalRuns(t *testing.T) {
	db := openTestDB(t, "runs.db")
	seedBundle(t, db)
	insert := func(ruleID, conclusion, createdAt string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO findings (hospital_id, bundle_id, rule_id, rule_version, subject, conclusion, detail, created_at)
			VALUES ('h-test', 'bundle-1', ?, '1', 's', ?, '{}', ?)`, ruleID, conclusion, createdAt); err != nil {
			t.Fatal(err)
		}
	}
	// 两簇：10:00:00-10:00:30 一簇（2 行），10:05:00 一簇（1 行）。
	insert("r1", "FAIL", "2026-10-20 10:00:00")
	insert("r2", "FAIL", "2026-10-20 10:00:30")
	insert("r3", "UNKNOWN", "2026-10-20 10:05:00")
	if err := backfillEvalRuns(db); err != nil {
		t.Fatal(err)
	}
	var runs int
	if err := db.QueryRow(`SELECT COUNT(*) FROM eval_runs WHERE bundle_id = 'bundle-1'`).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 2 {
		t.Fatalf("回填应建 2 轮，实际 %d", runs)
	}
	var untagged int
	if err := db.QueryRow(`SELECT COUNT(*) FROM findings WHERE bundle_id = 'bundle-1' AND eval_run_id IS NULL`).Scan(&untagged); err != nil {
		t.Fatal(err)
	}
	if untagged != 0 {
		t.Fatalf("回填后不应有未打轮次号的问题行，实际 %d", untagged)
	}
	// 幂等：再跑一次不新增轮次。
	if err := backfillEvalRuns(db); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM eval_runs WHERE bundle_id = 'bundle-1'`).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 2 {
		t.Fatalf("回填幂等失败，轮次数 %d", runs)
	}
}

// M37-fix3：最新轮次为空（0 问题）时，报告汇总为空、快照记下该轮次号，
// 绝不能回退到上一轮的问题行（此前 MSSQL 干净重评后报告仍显示 FAIL 4）。
func TestGenerateReportEmptyLatestRun(t *testing.T) {
	db := openTestDB(t, "empty.db")
	seedBundle(t, db)
	res, err := db.Exec(`INSERT INTO eval_runs (bundle_id, hospital_id, baseline_mode, baselines_applied, findings_count, created_at)
		VALUES ('bundle-1', 'h-test', 'auto', '[]', 2, '2026-10-20 10:00:00')`)
	if err != nil {
		t.Fatal(err)
	}
	run1, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	for _, ruleID := range []string{"r1", "r2"} {
		if _, err := db.Exec(`INSERT INTO findings (hospital_id, bundle_id, rule_id, rule_version, subject, conclusion, detail, eval_run_id, created_at)
			VALUES ('h-test', 'bundle-1', ?, '1', 's', 'FAIL', '{}', ?, '2026-10-20 10:00:00')`, ruleID, run1); err != nil {
			t.Fatal(err)
		}
	}
	// 第二轮：空轮次（0 问题），比第一轮新。
	res, err = db.Exec(`INSERT INTO eval_runs (bundle_id, hospital_id, baseline_mode, baselines_applied, findings_count, created_at)
		VALUES ('bundle-1', 'h-test', 'auto', '[]', 0, '2026-10-20 10:05:00')`)
	if err != nil {
		t.Fatal(err)
	}
	run2, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	repID, err := GenerateReport(db, "h-test", "p1", "bundle-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	snap, err := GetReportSnapshot(db, repID)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		ConclusionSummary map[string]any `json:"conclusion_summary"`
		LatestEvalRunID   int64          `json:"latest_eval_run_id"`
		Findings          []any          `json:"findings"`
	}
	if err := json.Unmarshal([]byte(snap), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.ConclusionSummary) != 0 {
		t.Fatalf("空轮次报告汇总应为空，实际 %v", parsed.ConclusionSummary)
	}
	if parsed.LatestEvalRunID != run2 {
		t.Fatalf("快照最新轮次号应为 %d，实际 %d", run2, parsed.LatestEvalRunID)
	}
	if len(parsed.Findings) != 2 {
		t.Fatalf("快照 findings 仍应存全部轮次（2 行），实际 %d", len(parsed.Findings))
	}
}

// M37-fix4：最新轮次号取 eval_runs 最大 ID，空轮次（0 问题）也返回；无轮次时 ok=false。
func TestLatestEvalRun(t *testing.T) {
	db := openTestDB(t, "latest-run.db")
	seedBundle(t, db)
	r1, err := db.Exec(`INSERT INTO eval_runs (bundle_id, hospital_id, baseline_mode, findings_count) VALUES ('bundle-1', 'h-test', 'auto', 3)`)
	if err != nil {
		t.Fatal(err)
	}
	id1, _ := r1.LastInsertId()
	r2, err := db.Exec(`INSERT INTO eval_runs (bundle_id, hospital_id, baseline_mode, findings_count) VALUES ('bundle-1', 'h-test', 'auto', 0)`)
	if err != nil {
		t.Fatal(err)
	}
	id2, _ := r2.LastInsertId()
	id, count, ok, err := LatestEvalRun(db, "bundle-1")
	if err != nil || !ok || id != id2 || count != 0 {
		t.Fatalf("最新轮次应为空轮次（id %d、count 0），实际 id=%d count=%d ok=%v err=%v", id2, id, count, ok, err)
	}
	if id1 == id2 {
		t.Fatalf("两轮 ID 应不同，实际 %d", id1)
	}
	if _, _, ok, err := LatestEvalRun(db, "bundle-none"); err != nil || ok {
		t.Fatalf("无轮次的包应 ok=false，实际 ok=%v err=%v", ok, err)
	}
}
