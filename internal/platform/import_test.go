package platform

import (
	"fmt"
	"testing"
)

// M37-1.2：ListBundles 只返回 100 条时，老对象的最近审计不能从列表算；
// LatestBundles 必须返回每个资产最新导入的包，不受 100 条上限影响。
func TestLatestBundlesBeyondListLimit(t *testing.T) {
	db := tokenTestDB(t)
	if _, err := db.Exec(`INSERT INTO hospitals (id, name) VALUES ('h1', 'H1')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO collection_plans (id, hospital_id, name, profile, spec, created_by)
		VALUES ('p1', 'h1', 'P1', 'prof', '{}', 'web')`); err != nil {
		t.Fatal(err)
	}
	insert := func(id, asset, ts string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO fact_bundles
			(id, plan_id, hospital_id, asset_id, schema_version, adapter, execution, bundle, imported_at)
			VALUES (?, 'p1', 'h1', ?, '1', 'db-mysql', 'COMPLETE', '{"facts":[],"receipts":[]}', ?)`,
			id, asset, ts); err != nil {
			t.Fatal(err)
		}
	}
	// a-buried 只有 1 个很旧的包：全局 DESC 排第 121 位，ListBundles 的 100 条里没有它。
	insert("b-buried", "a-buried", "2026-01-01 10:00:00")
	// a-old 60 个包，最新 2026-01-30；a-new 60 个包，最新 2026-02-28。
	for i := 0; i < 60; i++ {
		insert(fmt.Sprintf("b-old-%02d", i), "a-old", fmt.Sprintf("2026-01-%02d 10:00:00", i%30+1))
		insert(fmt.Sprintf("b-new-%02d", i), "a-new", fmt.Sprintf("2026-02-%02d 10:00:00", i%28+1))
	}
	// 121 个包已入库；先确认 ListBundles 确实只返回 100 条且不含 a-buried。
	listed, err := ListBundles(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 100 {
		t.Fatalf("ListBundles 应返回 100 条，实际 %d 条", len(listed))
	}
	for _, b := range listed {
		if b.AssetID == "a-buried" {
			t.Fatal("ListBundles 不应包含 a-buried（超出 100 条上限）")
		}
	}
	latest, err := LatestBundles(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) != 3 {
		t.Fatalf("LatestBundles 应返回 3 个资产的最新包，实际 %d 条", len(latest))
	}
	want := map[string]string{
		"a-buried": "2026-01-01 10:00:00",
		"a-old":    "2026-01-30 10:00:00",
		"a-new":    "2026-02-28 10:00:00",
	}
	for _, b := range latest {
		if want[b.AssetID] != b.ImportedAt {
			t.Errorf("资产 %s 最新包时间应为 %s，实际 %s（包 %s）",
				b.AssetID, want[b.AssetID], b.ImportedAt, b.ID)
		}
	}
}
