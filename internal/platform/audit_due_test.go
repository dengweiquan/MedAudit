package platform

import (
	"testing"
	"time"
)

func TestListAuditDue(t *testing.T) {
	db := tokenTestDB(t)
	if _, err := db.Exec(`INSERT INTO hospitals (id, name) VALUES ('h', 'H')`); err != nil {
		t.Fatal(err)
	}
	for _, a := range []struct{ id, kind string }{{"a-old", "db-mysql"}, {"a-new", "host"}, {"a-never", "db-pg"}, {"a-soon", "host"}, {"a-unk", "unknown"}} {
		if _, err := db.Exec(`INSERT INTO assets (id, hospital_id, kind, name) VALUES (?, 'h', ?, ?)`, a.id, a.kind, a.id); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	if _, err := db.Exec(`INSERT INTO collection_plans (id, hospital_id, name, profile, spec, created_by) VALUES ('p', 'h', 'p', 'x', '{}', 't')`); err != nil {
		t.Fatal(err)
	}
	for _, b := range []struct{ id, asset, at string }{
		{"b1", "a-old", "2026-09-01 08:00:00"},
		{"b2", "a-new", "2026-10-20 08:00:00"},
		{"b3", "a-soon", "2026-10-01 08:00:00"},
	} {
		if _, err := db.Exec(`INSERT INTO fact_bundles (id, plan_id, hospital_id, asset_id, schema_version, adapter, execution, bundle, imported_at)
			VALUES (?, 'p', 'h', ?, '1', 'x', 'COMPLETE', '{}', ?)`, b.id, b.asset, b.at); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ListAuditDue(db, 30, now)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ id, status string }{{"a-old", "overdue"}, {"a-never", "never"}, {"a-soon", "due_soon"}, {"a-new", "ok"}}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i, w := range want {
		if got[i].AssetID != w.id || got[i].Status != w.status {
			t.Fatalf("#%d = %s/%s, want %s/%s", i, got[i].AssetID, got[i].Status, w.id, w.status)
		}
	}
	if got[0].DaysLeft >= 0 {
		t.Fatalf("逾期对象 DaysLeft 应为负, got %d", got[0].DaysLeft)
	}
}
