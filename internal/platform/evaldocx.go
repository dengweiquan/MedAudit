package platform

import (
	"fmt"
	"strings"

	"medaudit/internal/facts"
	"medaudit/internal/rules"
)

// RenderEvalDocx 离线评估报告（M14）：直接由事实包 + 规则引擎结果渲染，
// 不依赖平台库。供 maoffeval 在隔离现场本地出 Word 报告；
// 与服务端报告同为「结论快照」，页眉注明离线口径。
func RenderEvalDocx(b *facts.FactBundle, results []rules.TechnicalResult) ([]byte, error) {
	counts := map[facts.Conclusion]int{}
	var fails []rules.TechnicalResult
	for _, r := range results {
		counts[r.Conclusion]++
		if r.Conclusion == facts.ConclusionFail {
			fails = append(fails, r)
		}
	}
	var sb strings.Builder
	sb.WriteString(docxPara("MedAudit 离线评估报告", "Title"))
	sb.WriteString(docxTable([][]string{
		{"事实包", b.BundleID},
		{"医院", b.Scope.HospitalID},
		{"资产", b.Scope.AssetID},
		{"适配器", string(b.Collector.Adapter) + " " + b.Collector.AdapterVersion},
		{"目标版本", b.Scope.TargetVersion},
		{"执行状态", string(b.Execution)},
		{"事实 / 收据", fmt.Sprintf("%d / %d", len(b.Facts), len(b.Receipts))},
		{"口径", "本报告由 ma 在本地以同一规则引擎离线生成；结论与服务端评估同口径，未回传平台库。"},
	}))
	sb.WriteString(docxPara("结论汇总", "Heading1"))
	sb.WriteString(docxPara(fmt.Sprintf("共 %d 条：PASS %d、FAIL %d、UNKNOWN %d、NOT_RUN %d、NOT_APPLICABLE %d",
		len(results), counts[facts.ConclusionPass], counts[facts.ConclusionFail],
		counts[facts.ConclusionUnknown], counts[facts.ConclusionNotRun], counts[facts.ConclusionNotApplicable]), ""))
	sb.WriteString(docxPara("问题清单（FAIL）", "Heading1"))
	if len(fails) == 0 {
		sb.WriteString(docxPara("无 FAIL 问题。", ""))
	} else {
		rows := [][]string{{"规则", "主体", "风险", "明细"}}
		for _, r := range fails {
			rows = append(rows, []string{r.RuleID, r.Subject, string(r.Risk), r.Detail})
		}
		sb.WriteString(docxTable(rows))
	}
	sb.WriteString(docxPara("全部结论", "Heading1"))
	rows := [][]string{{"规则", "主体", "结论"}}
	const capN = 500
	for i, r := range results {
		if i >= capN {
			break
		}
		rows = append(rows, []string{r.RuleID, r.Subject, string(r.Conclusion)})
	}
	sb.WriteString(docxTable(rows))
	if len(results) > capN {
		sb.WriteString(docxPara(fmt.Sprintf("（全部结论共 %d 条，此处截断为前 %d 条；完整数据见 --json 输出）", len(results), capN), ""))
	}
	return packDocx(sb.String())
}
