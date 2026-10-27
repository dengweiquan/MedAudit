package platform

import (
	"database/sql"
	"path/filepath"
	"testing"

	"medaudit/internal/rules"
)

// M37-fix2-3：基线列表新增 created_at 字段（医院模式下拉用创建日期区分
// 同适配器同版本的基线）。SELECT 与 Scan 列数不一致会直接报错，本用例
// 覆盖新列接线。
func TestListBaselinesIncludesCreatedAt(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "baselines.db"))
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
	allows := []rules.BaselineAllow{{Subject: "root@localhost", Kind: "privilege", Value: "SUPER"}}
	if err := CreateBaseline(db, "bl-1", "h-test", "db-mysql", allows, "admin"); err != nil {
		t.Fatal(err)
	}
	rows, err := ListBaselines(db, "h-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("应列出 1 条基线，实际 %d", len(rows))
	}
	r := rows[0]
	if r.ID != "bl-1" || r.Target != "db-mysql" || r.Version != 1 {
		t.Fatalf("基线行字段不对，实际 %+v", r)
	}
	if r.CreatedAt == "" {
		t.Error("基线列表应返回 created_at")
	}
}
