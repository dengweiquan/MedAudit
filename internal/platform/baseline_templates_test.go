package platform

import (
	"strings"
	"testing"

	"medaudit/internal/facts"
	"medaudit/internal/rules"
)

func TestBaselineTemplatesParse(t *testing.T) {
	list, errs := ListBaselineTemplates()
	if len(errs) > 0 {
		t.Fatalf("模板解析错误: %v", errs)
	}
	systems := map[string]bool{}
	for _, tpl := range list {
		systems[tpl.System] = true
		if tpl.Status == "draft" && len(tpl.Placeholders) == 0 {
			t.Errorf("%s 为草稿模板，主体应使用占位符而非具体账号", tpl.ID)
		}
	}
	for _, s := range []string{"HIS", "LIS", "PACS", "通用"} {
		if !systems[s] {
			t.Errorf("缺少 %s 类模板", s)
		}
	}
}

// 套用内置模板后，演示库中对应内置账号的问题应被基线放行。
func TestBaselineTemplateApplyClearsBuiltinFindings(t *testing.T) {
	cases := []struct {
		zip, tpl, rule string
		subjects       []string
	}{
		{"demo-oracle-1", "builtin-oracle", "db.oracle.dba_role", []string{"SYS", "SYSTEM"}},
		{"demo-mysql-1", "builtin-mysql8", "db.mysql.global_admin", []string{"mysql.session@localhost", "mysql.sys@localhost", "mysql.infoschema@localhost", "root@localhost"}},
	}
	for _, c := range cases {
		t.Run(c.tpl, func(t *testing.T) {
			db := tokenTestDB(t)
			b, err := facts.ReadZip("../../pilot/demo-data/" + c.zip + ".zip")
			if err != nil {
				t.Fatal(err)
			}
			db.Exec(`INSERT INTO hospitals (id, name) VALUES ('h', 'H')`)
			added, created, err := ApplyBaselineTemplate(db, c.tpl, TemplateApply{HospitalID: "h", BaselineID: "bl-" + c.tpl, CreatedBy: "t"})
			if err != nil || !created || len(added) == 0 {
				t.Fatalf("apply: added=%d created=%v err=%v", len(added), created, err)
			}
			bl, err := LoadBaseline(db, "bl-"+c.tpl)
			if err != nil {
				t.Fatal(err)
			}
			reg := rules.DefaultRegistry()
			fails := func(base *rules.Baseline) map[string]bool {
				m := map[string]bool{}
				for _, r := range reg.Evaluate(b, base) {
					if r.RuleID == c.rule && r.Conclusion == facts.ConclusionFail {
						m[r.Subject] = true
					}
				}
				return m
			}
			before, after := fails(&rules.Baseline{}), fails(bl)
			for _, s := range c.subjects {
				if !before[s] {
					t.Errorf("演示数据中 %s 本应命中 %s", s, c.rule)
				}
				if after[s] {
					t.Errorf("套用模板后 %s 仍命中 %s", s, c.rule)
				}
			}
			// 再套一次不重复添加
			again, _, err := ApplyBaselineTemplate(db, c.tpl, TemplateApply{HospitalID: "h", BaselineID: "bl-" + c.tpl})
			if err != nil || len(again) != 0 {
				t.Fatalf("重复套用应无新增: %d %v", len(again), err)
			}
		})
	}
}

func TestBaselineTemplatePlaceholders(t *testing.T) {
	db := tokenTestDB(t)
	db.Exec(`INSERT INTO hospitals (id, name) VALUES ('h', 'H')`)
	_, _, err := ApplyBaselineTemplate(db, "his-oracle", TemplateApply{HospitalID: "h", BaselineID: "bl-his"})
	if err == nil || !strings.Contains(err.Error(), "{HIS应用账号}") {
		t.Fatalf("未填占位符应报错, got %v", err)
	}
	added, _, err := ApplyBaselineTemplate(db, "his-oracle", TemplateApply{
		HospitalID: "h", BaselineID: "bl-his",
		Values: map[string]string{"{HIS应用账号}": "HISAPP"}, Skip: []int{1},
	})
	if err != nil || len(added) != 1 || added[0].Subject != "HISAPP" || added[0].Value != "DBA" {
		t.Fatalf("added=%+v err=%v", added, err)
	}
	// 目标不一致的基线拒绝
	if _, _, err := ApplyBaselineTemplate(db, "builtin-mysql8", TemplateApply{HospitalID: "h", BaselineID: "bl-his"}); err == nil {
		t.Fatal("目标不一致应拒绝")
	}
}
