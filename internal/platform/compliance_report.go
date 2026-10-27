package platform

import (
	"os"
	"strings"

	"medaudit/internal/facts"
	"medaudit/internal/rules"
)

// 报告的合规逐条判定：对每个启用的合规框架，按条款给出结论。
//   fail      不满足：对应规则在本次评估中有不通过的问题
//   unknown   无法判定：对应规则证据不足或未执行，且没有不通过
//   pass      满足：对应且适用的规则全部通过（含经基线放行的例外）
//   na        不涉及：对应规则对本对象类型不适用（或已在本站停用）
//   unchecked 本平台未检查：该条款不在本平台技术检查范围，需人工测评
// 「满足」仅就本平台的技术检查项而言，条款中的管理类要求不在其内。

// 规则在本次报告中的结果。
const (
	outFail     = "fail"
	outUnknown  = "unknown"
	outPass     = "pass"
	outExempt   = "exempt" // 技术上命中，但经基线放行
	outNA       = "na"
	outDisabled = "disabled"
)

// ComplianceRule 条款依据中的一条规则结果。
type ComplianceRule struct {
	RuleID  string `json:"rule_id"`
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
	Fails   int    `json:"fails,omitempty"`
}

// ComplianceClause 一个条款的判定。
type ComplianceClause struct {
	ID     string           `json:"id"`
	Ref    string           `json:"ref,omitempty"`
	Group  string           `json:"group"`
	Title  string           `json:"title"`
	Status string           `json:"status"` // fail | unknown | pass | na | unchecked
	Rules  []ComplianceRule `json:"rules,omitempty"`
}

// ComplianceResult 一个框架的逐条判定。
type ComplianceResult struct {
	ID      string             `json:"id"`
	Name    string             `json:"name"`
	Short   string             `json:"short"`
	Status  string             `json:"status"` // 框架状态 verified | draft
	Counts  map[string]int     `json:"counts"`
	Clauses []ComplianceClause `json:"clauses"`
}

// EnabledFrameworks 参与报告的框架：已核实的全部启用，草稿框架需列入
// MEDAUDIT_COMPLIANCE_ENABLE（逗号分隔 id）。站点目录 MEDAUDIT_COMPLIANCE_DIR
// （缺省 /etc/medaudit/compliance）中的文件新增或按 id 覆盖内置框架。
func EnabledFrameworks() ([]rules.Framework, []string) {
	dir := os.Getenv("MEDAUDIT_COMPLIANCE_DIR")
	if dir == "" {
		dir = "/etc/medaudit/compliance"
	}
	all, errs := rules.LoadFrameworks(dir)
	enable := map[string]bool{}
	for _, id := range strings.Split(os.Getenv("MEDAUDIT_COMPLIANCE_ENABLE"), ",") {
		if id = strings.TrimSpace(id); id != "" {
			enable[id] = true
		}
	}
	var out []rules.Framework
	for _, f := range all {
		if f.Status == "verified" || enable[f.ID] {
			out = append(out, f)
		}
	}
	return out, errs
}

// latestRun 取最近一轮评估落库的问题（同一 created_at 为一轮）。
func latestRun(findings []FindingRow) []FindingRow {
	last := ""
	for _, f := range findings {
		if f.CreatedAt > last {
			last = f.CreatedAt
		}
	}
	var out []FindingRow
	for _, f := range findings {
		if f.CreatedAt == last {
			out = append(out, f)
		}
	}
	return out
}

// ruleOutcomes 合并技术口径（无基线）与落库口径（含基线与启停）得出每条规则的结果。
func ruleOutcomes(b *facts.FactBundle, findings []FindingRow, disabled map[string]bool) map[string]ComplianceRule {
	tech := map[string]facts.Conclusion{}
	for _, r := range rules.DefaultRegistry().Evaluate(b, &rules.Baseline{}) {
		// 同一规则只在命中时会有多条结果（均为 FAIL），其余情况一条。
		if _, ok := tech[r.RuleID]; !ok || r.Conclusion == facts.ConclusionFail {
			tech[r.RuleID] = r.Conclusion
		}
	}
	fails, unknown := map[string]int{}, map[string]bool{}
	for _, f := range latestRun(findings) {
		switch f.Conclusion {
		case string(facts.ConclusionFail):
			fails[f.RuleID]++
		case string(facts.ConclusionUnknown), string(facts.ConclusionNotRun):
			unknown[f.RuleID] = true
		}
	}
	out := map[string]ComplianceRule{}
	for id, c := range tech {
		o := ComplianceRule{RuleID: id, Name: ruleName(id)}
		switch {
		case c == facts.ConclusionNotApplicable:
			o.Outcome = outNA
		case disabled[id]:
			o.Outcome = outDisabled
		case fails[id] > 0:
			o.Outcome, o.Fails = outFail, fails[id]
		case unknown[id] || c == facts.ConclusionUnknown || c == facts.ConclusionNotRun:
			o.Outcome = outUnknown
		case c == facts.ConclusionFail:
			o.Outcome = outExempt
		default:
			o.Outcome = outPass
		}
		out[id] = o
	}
	return out
}

// complianceSection 计算全部启用框架的逐条判定。
func complianceSection(b *facts.FactBundle, findings []FindingRow, disabled map[string]bool) []ComplianceResult {
	fws, _ := EnabledFrameworks()
	if len(fws) == 0 {
		return nil
	}
	outcomes := ruleOutcomes(b, findings, disabled)
	var res []ComplianceResult
	for _, fw := range fws {
		r := ComplianceResult{ID: fw.ID, Name: fw.Name, Short: fw.Short, Status: fw.Status, Counts: map[string]int{}}
		for _, c := range fw.Controls {
			cl := ComplianceClause{ID: c.ID, Ref: c.Ref, Group: c.Group, Title: c.Title}
			var hasFail, hasUnknown, hasPass bool
			for _, rid := range c.Rules {
				o, ok := outcomes[rid]
				if !ok {
					continue
				}
				switch o.Outcome {
				case outFail:
					hasFail = true
				case outUnknown:
					hasUnknown = true
				case outPass, outExempt:
					hasPass = true
				case outNA:
					continue // 不适用的规则不列入依据
				}
				cl.Rules = append(cl.Rules, o)
			}
			switch {
			case len(c.Rules) == 0:
				cl.Status = "unchecked"
			case hasFail:
				cl.Status = "fail"
			case hasUnknown:
				cl.Status = "unknown"
			case hasPass:
				cl.Status = "pass"
			default:
				cl.Status = "na"
			}
			r.Counts[cl.Status]++
			r.Clauses = append(r.Clauses, cl)
		}
		res = append(res, r)
	}
	return res
}
