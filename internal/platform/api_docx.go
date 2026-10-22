package platform

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"medaudit/internal/apiaudit"
)

// RenderAPIAuditDocx 把业务接口越权检测报告 JSON 渲染为 .docx（M10-1）。
// 结构：元信息 → 结论汇总 → 越权命中（FAIL）清单 → 全量探针清单（上限 500 条，超出注明）。
func RenderAPIAuditDocx(reportJSON string) ([]byte, error) {
	var rep apiaudit.Report
	if err := json.Unmarshal([]byte(reportJSON), &rep); err != nil {
		return nil, fmt.Errorf("API 报告解析失败: %w", err)
	}
	var body strings.Builder
	body.WriteString(docxPara("MedAudit 业务接口越权检测报告", "Title"))
	body.WriteString(docxTable([][]string{
		{"报告", rep.ReportID},
		{"目标", rep.Target},
		{"规格来源", rep.SpecSource},
		{"执行状态", rep.Execution},
		{"开始", DisplayTime(rep.StartedAt)},
		{"结束", DisplayTime(rep.FinishedAt)},
		{"参与身份", strings.Join(rep.Identities, "、")},
	}))

	keys := make([]string, 0, len(rep.Summary))
	for k := range rep.Summary {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, rep.Summary[k]))
	}
	body.WriteString(docxPara("结论汇总", "Heading1"))
	body.WriteString(docxPara(fmt.Sprintf("探针共 %d 项：%s。判定口径：仅当低权身份实际读到金丝雀数据才记 FAIL；写操作默认不执行记 NOT_RUN。", len(rep.Checks), strings.Join(parts, "；")), ""))

	rowOf := func(c apiaudit.Check) []string {
		detail := c.Detail
		if len([]rune(detail)) > 120 {
			detail = string([]rune(detail)[:120]) + "…"
		}
		status := "—"
		if c.Status != 0 {
			status = fmt.Sprintf("%d", c.Status)
		}
		return []string{c.Endpoint, c.Identity, c.Probe, string(c.Expectation), status, string(c.Conclusion), detail}
	}
	header := []string{"端点", "身份", "探针", "期望", "HTTP", "结论", "明细"}

	body.WriteString(docxPara("越权命中（FAIL）", "Heading1"))
	failRows := [][]string{header}
	for _, c := range rep.Checks {
		if c.Conclusion == apiaudit.ConclFail {
			failRows = append(failRows, rowOf(c))
		}
	}
	if len(failRows) > 1 {
		body.WriteString(docxTable(failRows))
	} else {
		body.WriteString(docxPara("无越权命中。", ""))
	}

	body.WriteString(docxPara("全量探针清单", "Heading1"))
	const maxRows = 500
	allRows := [][]string{header}
	for i, c := range rep.Checks {
		if i >= maxRows {
			break
		}
		allRows = append(allRows, rowOf(c))
	}
	body.WriteString(docxTable(allRows))
	if len(rep.Checks) > maxRows {
		body.WriteString(docxPara(fmt.Sprintf("注：探针共 %d 项，清单截断为前 %d 项；完整结果见平台报告详情。", len(rep.Checks), maxRows), ""))
	}
	return packDocx(body.String())
}
