package platform

import (
	"os"
	"path/filepath"
	"testing"

	"medaudit/internal/facts"
	"medaudit/internal/rules"
)

func clauseByID(t *testing.T, r ComplianceResult, id string) ComplianceClause {
	t.Helper()
	for _, c := range r.Clauses {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("框架 %s 缺少条款 %s", r.ID, id)
	return ComplianceClause{}
}

// 用技术口径结果模拟落库：FAIL/UNKNOWN 进 findings。
func techFindings(b *facts.FactBundle, base *rules.Baseline) []FindingRow {
	var out []FindingRow
	for _, r := range rules.DefaultRegistry().Evaluate(b, base) {
		if r.Conclusion == facts.ConclusionPass || r.Conclusion == facts.ConclusionNotApplicable {
			continue
		}
		out = append(out, FindingRow{RuleID: r.RuleID, Subject: r.Subject, Conclusion: string(r.Conclusion), CreatedAt: "2026-10-27 01:00:00"})
	}
	return out
}

func TestComplianceSection(t *testing.T) {
	t.Setenv("MEDAUDIT_COMPLIANCE_DIR", t.TempDir())
	t.Setenv("MEDAUDIT_COMPLIANCE_ENABLE", "")
	b, err := facts.ReadZip("../../pilot/demo-data/demo-mysql-1.zip")
	if err != nil {
		t.Fatal(err)
	}
	res := complianceSection(b, techFindings(b, &rules.Baseline{}), nil)
	if len(res) != 1 || res[0].ID != "djbh2-l3" {
		t.Fatalf("默认只启用已核实框架, got %d", len(res))
	}
	r := res[0]
	if c := clauseByID(t, r, "8.1.4.2 d)"); c.Status != "fail" {
		t.Errorf("8.1.4.2 d) 应不满足, got %s", c.Status)
	}
	if c := clauseByID(t, r, "8.1.4.3 a)"); c.Status != "unchecked" {
		t.Errorf("8.1.4.3 a) 应为本平台未检查, got %s", c.Status)
	}
	total := 0
	for _, n := range r.Counts {
		total += n
	}
	if total != len(r.Clauses) {
		t.Errorf("计数合计 %d != 条款数 %d", total, len(r.Clauses))
	}
	// 只有 MySQL 规则的条款在 MySQL 包上不应出现 OS 规则依据
	for _, c := range r.Clauses {
		for _, rr := range c.Rules {
			if rr.Outcome == outNA {
				t.Errorf("不适用规则不应列入依据: %s", rr.RuleID)
			}
		}
	}

	// 旧一轮问题不影响：最新一轮为空 → 有 FAIL 的规则视为经基线放行（满足）
	old := techFindings(b, &rules.Baseline{})
	for i := range old {
		old[i].CreatedAt = "2026-10-01 00:00:00"
	}
	latest := []FindingRow{{RuleID: "x", Conclusion: "NOT_RUN", CreatedAt: "2026-10-27 02:00:00"}}
	res = complianceSection(b, append(old, latest...), nil)
	c := clauseByID(t, res[0], "8.1.4.2 d)")
	if c.Status != "pass" {
		t.Errorf("基线全部放行后 8.1.4.2 d) 应满足, got %s", c.Status)
	}
	exempt := false
	for _, rr := range c.Rules {
		exempt = exempt || rr.Outcome == outExempt
	}
	if !exempt {
		t.Error("依据中应标出基线放行")
	}

	// 停用规则：不计入判定
	disabled := map[string]bool{"db.mysql.remote_no_tls": true}
	res = complianceSection(b, nil, disabled)
	if c := clauseByID(t, res[0], "8.1.4.1 c)"); c.Status != "na" {
		t.Errorf("唯一规则停用后 8.1.4.1 c) 应为不涉及, got %s", c.Status)
	}
}

func TestComplianceFrameworkEnableAndOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MEDAUDIT_COMPLIANCE_DIR", dir)
	t.Setenv("MEDAUDIT_COMPLIANCE_ENABLE", "medical-draft")
	fws, errs := EnabledFrameworks()
	if len(errs) != 0 || len(fws) != 2 {
		t.Fatalf("草稿框架列入 ENABLE 后应启用: %d %v", len(fws), errs)
	}
	// 站点覆盖：核实后的医疗框架无需 ENABLE
	os.WriteFile(filepath.Join(dir, "medical.yaml"), []byte(`id: medical-draft
name: 医疗卫生机构网络安全管理办法（核实版）
status: verified
controls:
  - {id: 第X条, ref: 《办法》第X条, group: 权限管理, title: 最小授权, rules: [db.mysql.global_admin]}
`), 0o644)
	os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("id: [\n"), 0o644)
	t.Setenv("MEDAUDIT_COMPLIANCE_ENABLE", "")
	fws, errs = EnabledFrameworks()
	if len(errs) != 1 || len(fws) != 2 || fws[1].Name != "医疗卫生机构网络安全管理办法（核实版）" {
		t.Fatalf("站点覆盖失败: %+v errs=%v", fws, errs)
	}
	b, _ := facts.ReadZip("../../pilot/demo-data/demo-mysql-1.zip")
	res := complianceSection(b, techFindings(b, &rules.Baseline{}), nil)
	if c := clauseByID(t, res[1], "第X条"); c.Status != "fail" || c.Ref == "" {
		t.Fatalf("站点框架判定 = %+v", c)
	}
}
