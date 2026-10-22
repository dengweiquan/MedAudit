package platform

import (
	"encoding/json"

	"medaudit/internal/facts"
	"medaudit/internal/remediation"
)

// remediationSection 报告快照的「修复与回滚脚本」章节（M15）。
// 生成口径：报告生成时点，以落库 findings 的 evidence 事实 ID 在本包内解析
// 完整事实，逐条 FAIL 生成脚本。平台只生成、人工执行，绝不自动改目标权限。
// 返回 nil 表示本包无 FAIL（整段缺省，与 privilege_paths/drift 同哲学）。
func remediationSection(bundleRaw string, findings []FindingRow) any {
	failTotal := 0
	for _, f := range findings {
		if f.Conclusion == string(facts.ConclusionFail) {
			failTotal++
		}
	}
	if failTotal == 0 {
		return nil
	}
	var b facts.FactBundle
	if err := json.Unmarshal([]byte(bundleRaw), &b); err != nil {
		return map[string]any{"fail_total": failTotal, "generated": 0, "scripts": []remediation.Script{}}
	}
	byID := make(map[string]facts.Fact, len(b.Facts))
	// 实例上下文事实（*.instance）：不属任何单条 finding 的证据，但携带
	// home/配置路径等定位信息，附加给生成器把脚本从通用路径落到确切路径。
	var ctx []facts.Fact
	for _, f := range b.Facts {
		byID[f.FactID] = f
		if len(f.Source) > 9 && f.Source[len(f.Source)-9:] == ".instance" {
			ctx = append(ctx, f)
		}
	}
	const maxScripts = 500
	scripts := []remediation.Script{}
	generated := 0
	for _, f := range findings {
		if f.Conclusion != string(facts.ConclusionFail) {
			continue
		}
		var detail struct {
			Evidence []string `json:"evidence"`
		}
		_ = json.Unmarshal([]byte(f.Detail), &detail)
		ev := []facts.Fact{}
		for _, id := range detail.Evidence {
			if fact, ok := byID[id]; ok {
				ev = append(ev, fact)
			}
		}
		ev = append(ev, ctx...)
		s := remediation.Generate(f.RuleID, f.Subject, ev)
		if s == nil {
			continue
		}
		generated++
		if len(scripts) < maxScripts {
			s.FindingID = f.ID
			scripts = append(scripts, *s)
		}
	}
	return map[string]any{
		"fail_total": failTotal,
		"generated":  generated,
		"stored":     len(scripts),
		"scripts":    scripts,
		"note":       "脚本由平台按报告生成时点的证据事实生成，仅供人工评审后执行；平台不自动修改目标权限。回滚命令为生成时捕获的精确逆操作。",
	}
}
