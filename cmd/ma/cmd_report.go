package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// ---------- 报告 ----------

func cmdReport(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "o", value: true}})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, T("ma report <包id> [-o 报告.docx]", "ma report <bundle-id> [-o report.docx]")); err != nil {
		return err
	}
	bundleID := p.pos[0]
	out := p.str("o")
	if out == "" {
		out = "report-" + bundleID + ".docx"
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	target, err := findBundle(c, bundleID)
	if err != nil {
		return err
	}
	var created struct {
		ReportID string `json:"report_id"`
	}
	body := map[string]any{
		"hospital_id": target.HospitalID, "plan_id": target.PlanID,
		"bundle_id": target.ID, "created_by": c.username(),
	}
	if err := c.postJSON("/api/v1/reports", body, &created); err != nil {
		return err
	}
	_, raw, err := c.do("GET", "/api/v1/reports/"+escapePath(created.ReportID)+"/docx", nil)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		return err
	}
	fmt.Printf(T("报告 %s 已生成并下载到 %s（%d 字节）\n", "Report %s generated and downloaded to %s (%d bytes)\n"), created.ReportID, out, len(raw))
	return nil
}

func cmdReportList(args []string) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	var rows []reportRow
	if err := c.getJSON("/api/v1/reports", &rows); err != nil {
		return err
	}
	fmt.Printf("%-52s %-12s %-38s %s\n", T("报告", "REPORT"), T("医院", "HOSPITAL"), T("事实包", "BUNDLE"), T("生成时间", "CREATED"))
	for _, r := range rows {
		fmt.Printf("%-52s %-12s %-38s %s\n", r.ID, r.HospitalID, r.BundleID, r.CreatedAt)
	}
	fmt.Printf(T("共 %d 份\n", "%d in total\n"), len(rows))
	return nil
}

func fetchReport(c *client, id string) (*reportDetail, error) {
	var d reportDetail
	if err := c.getJSON("/api/v1/reports/"+escapePath(id), &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func cmdReportShow(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "j"}})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, T("ma reportshow <报告id> [-j]", "ma reportshow <report-id> [-j]")); err != nil {
		return err
	}
	id := p.pos[0]
	c, err := newClient()
	if err != nil {
		return err
	}
	if p.has("j") {
		var raw json.RawMessage
		if err := c.getJSON("/api/v1/reports/"+escapePath(id), &raw); err != nil {
			return err
		}
		return printJSON(raw)
	}
	d, err := fetchReport(c, id)
	if err != nil {
		return err
	}
	var meta *reportRow
	var rows []reportRow
	if err := c.getJSON("/api/v1/reports", &rows); err == nil {
		for i := range rows {
			if rows[i].ID == id {
				meta = &rows[i]
				break
			}
		}
	}
	by, at := "", d.GeneratedAt
	if meta != nil {
		by = meta.CreatedBy
		if meta.CreatedAt != "" {
			at = meta.CreatedAt
		}
	}
	fmt.Printf(T("报告 %s\n  医院 %s · 方案 %s · 事实包 %s\n  生成 %s by %s\n", "Report %s\n  Hospital %s · Plan %s · Bundle %s\n  Generated %s by %s\n"),
		id, d.HospitalID, d.PlanID, d.BundleID, at, by)
	fail := 0
	for _, f := range d.Findings {
		if f.Conclusion == "FAIL" {
			fail++
		}
	}
	fmt.Printf(T("  问题快照 %d 条（FAIL %d）\n", "  %d findings in snapshot (FAIL %d)\n"), len(d.Findings), fail)
	if d.Remediation != nil {
		fmt.Printf(T("  修复脚本：%d/%d 条 FAIL 已生成（ma reportfix 查看）\n", "  Remediation scripts: generated for %d/%d FAILs (see ma reportfix)\n"), d.Remediation.Generated, d.Remediation.FailTotal)
	}
	if len(d.PrivilegePaths) > 0 {
		fmt.Printf(T("  关联提权路径摘录 %d 条\n", "  %d correlation privilege paths excerpted\n"), len(d.PrivilegePaths))
	}
	if d.Drift != nil {
		fmt.Print(T("  含漂移对比章节\n", "  Includes a drift comparison section\n"))
	}
	return nil
}

func cmdReportScripts(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "r", value: true}})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, T("ma reportfix <报告id> [-r 规则]", "ma reportfix <report-id> [-r rule]")); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	d, err := fetchReport(c, p.pos[0])
	if err != nil {
		return err
	}
	if d.Remediation == nil || len(d.Remediation.Scripts) == 0 {
		fmt.Println(T("该报告无修复脚本（无 FAIL 或报告生成于 M15 之前）。", "This report has no remediation scripts (no FAILs, or the report predates M15)."))
		return nil
	}
	n := 0
	for _, s := range d.Remediation.Scripts {
		if p.str("r") != "" && s.RuleID != p.str("r") {
			continue
		}
		n++
		fmt.Printf(T("=== %s · %s\n-- 前置检查 --\n%s\n-- 修复 --\n%s\n-- 验证 --\n%s\n-- 回滚 --\n%s\n", "=== %s · %s\n-- Precheck --\n%s\n-- Fix --\n%s\n-- Verify --\n%s\n-- Rollback --\n%s\n"),
			s.RuleID, s.Subject, s.Precheck, s.Fix, s.Verify, s.Rollback)
		if s.Note != "" {
			fmt.Printf(T("-- 说明 --\n%s\n", "-- Note --\n%s\n"), s.Note)
		}
		fmt.Println()
	}
	fmt.Printf(T("共 %d 份脚本（报告内共 %d）\n", "%d scripts shown (%d in the report)\n"), n, len(d.Remediation.Scripts))
	return nil
}
