package platform

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"medaudit/internal/facts"
	"medaudit/internal/remediation"
)

// FixScriptForFinding 按问题取修复脚本（M35，供问题详情页页内展示）。
// 复用报告期脚本生成器：以落库 finding 的 evidence 事实 ID 在本包内解析
// 完整事实，逐条生成。规则无生成器或证据不足时返回 supported=false。
// 平台只生成、人工执行，绝不自动改目标权限。
func FixScriptForFinding(db *sql.DB, findingID int64) (*remediation.Script, bool, error) {
	var bundleID, ruleID, subject, detailRaw string
	err := db.QueryRow(`SELECT bundle_id, rule_id, subject, detail FROM findings WHERE id = ?`, findingID).
		Scan(&bundleID, &ruleID, &subject, &detailRaw)
	if err == sql.ErrNoRows {
		return nil, false, fmt.Errorf("问题 %d 不存在", findingID)
	}
	if err != nil {
		return nil, false, err
	}
	var bundleRaw string
	if err := db.QueryRow(`SELECT bundle FROM fact_bundles WHERE id = ?`, bundleID).Scan(&bundleRaw); err != nil {
		return nil, false, err
	}
	var b facts.FactBundle
	if err := json.Unmarshal([]byte(bundleRaw), &b); err != nil {
		return nil, false, err
	}
	byID := make(map[string]facts.Fact, len(b.Facts))
	var ctx []facts.Fact
	for _, f := range b.Facts {
		byID[f.FactID] = f
		if len(f.Source) > 9 && f.Source[len(f.Source)-9:] == ".instance" {
			ctx = append(ctx, f)
		}
	}
	var detail struct {
		Evidence []string `json:"evidence"`
	}
	_ = json.Unmarshal([]byte(detailRaw), &detail)
	ev := []facts.Fact{}
	for _, id := range detail.Evidence {
		if fact, ok := byID[id]; ok {
			ev = append(ev, fact)
		}
	}
	ev = append(ev, ctx...)
	s := remediation.Generate(ruleID, subject, ev)
	if s == nil {
		return nil, false, nil
	}
	s.FindingID = findingID
	return s, true, nil
}
