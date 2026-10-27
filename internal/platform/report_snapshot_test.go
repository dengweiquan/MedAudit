package platform

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// M37-fix2-1：报告是快照。先生成报告 A，再对同一包追加第二轮评估结果并
// 生成报告 B，A 的快照 findings 必须保持不变（仍只有第一轮），B 的快照
// 则含两轮（前端计最新一轮，见 web/src/util.test.ts）。
func TestGenerateReportSnapshotImmutable(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
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
	insertFinding := func(ruleID, conclusion, createdAt string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO findings (hospital_id, bundle_id, rule_id, rule_version, subject, conclusion, detail, created_at)
			VALUES ('h-test', 'bundle-1', ?, '1', 's', ?, '{}', ?)`, ruleID, conclusion, createdAt); err != nil {
			t.Fatal(err)
		}
	}
	// 第一轮：r1、r2 两条不通过。
	insertFinding("r1", "FAIL", "2026-10-20 10:00:00")
	insertFinding("r2", "FAIL", "2026-10-20 10:00:01")
	repA, err := GenerateReport(db, "h-test", "p1", "bundle-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	ruleIDs := func(reportID string) []string {
		t.Helper()
		snap, err := GetReportSnapshot(db, reportID)
		if err != nil {
			t.Fatal(err)
		}
		var parsed struct {
			Findings []struct {
				RuleID string `json:"rule_id"`
			} `json:"findings"`
		}
		if err := json.Unmarshal([]byte(snap), &parsed); err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, f := range parsed.Findings {
			ids = append(ids, f.RuleID)
		}
		return ids
	}
	if got := ruleIDs(repA); len(got) != 2 || got[0] != "r1" || got[1] != "r2" {
		t.Fatalf("报告 A 快照应只有第一轮 r1、r2，实际 %v", got)
	}
	// 第二轮：r1、r3 两条不通过（报告 ID 按 bundle + 秒级时间戳生成，隔 1 秒以上避免撞 ID）。
	insertFinding("r1", "FAIL", "2026-10-20 11:00:00")
	insertFinding("r3", "FAIL", "2026-10-20 11:00:01")
	time.Sleep(1100 * time.Millisecond)
	repB, err := GenerateReport(db, "h-test", "p1", "bundle-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if got := ruleIDs(repB); len(got) != 4 {
		t.Fatalf("报告 B 快照应含两轮共 4 条，实际 %v", got)
	}
	// 旧报告 A 重读：快照不得被第二轮污染。
	if got := ruleIDs(repA); len(got) != 2 || got[0] != "r1" || got[1] != "r2" {
		t.Fatalf("重评并生成报告 B 后，报告 A 快照应保持不变，实际 %v", got)
	}
}
