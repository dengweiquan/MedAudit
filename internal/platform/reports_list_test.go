package platform

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestListReportsAssetID(t *testing.T) {
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
	if _, err := db.Exec(`INSERT INTO reports (id, hospital_id, plan_id, snapshot, created_by, created_at)
		VALUES ('rep-1', 'h-test', 'p1', '{"bundle_id":"bundle-1"}', 'admin', '2026-10-20 11:00:00')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO reports (id, hospital_id, plan_id, snapshot, created_by, created_at)
		VALUES ('rep-2', 'h-test', 'p1', '{"bundle_id":"bundle-gone"}', 'admin', '2026-10-20 12:00:00')`); err != nil {
		t.Fatal(err)
	}
	rows, err := ListReports(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("应列出 2 份报告，实际 %d", len(rows))
	}
	// 按 created_at 倒序：rep-2 在前（包已不存在，asset_id 为空）；rep-1 在后。
	if rows[0].ID != "rep-2" || rows[0].AssetID != "" {
		t.Fatalf("包不存在的报告 asset_id 应为空，实际 %+v", rows[0])
	}
	if rows[1].ID != "rep-1" || rows[1].AssetID != "a-mysql" {
		t.Fatalf("报告 asset_id 应经事实包派生为 a-mysql，实际 %+v", rows[1])
	}
}
