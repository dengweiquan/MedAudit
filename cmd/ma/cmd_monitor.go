package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ---------- 持续监测：告警、复检到期、定期自动复检、操作日志、基线模板、合规框架 ----------

// listHospital 列表类命令的医院过滤：-h 覆盖或已设上下文时过滤，否则显示全部。
func listHospital(c *client, override string) string {
	h, err := c.contextHospital(override)
	if err != nil {
		return ""
	}
	return h
}

func short(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

type alertRow struct {
	ID         int64  `json:"id"`
	HospitalID string `json:"hospital_id"`
	AssetID    string `json:"asset_id"`
	Kind       string `json:"kind"`
	AddedCount int    `json:"added_count"`
	Title      string `json:"title"`
	Items      []struct {
		Category string `json:"category"`
		Subject  string `json:"subject"`
		Detail   string `json:"detail"`
	} `json:"items"`
	Error     string `json:"error"`
	CreatedAt string `json:"created_at"`
	AckedBy   string `json:"acked_by"`
	AckedAt   string `json:"acked_at"`
}

func cmdAlertList(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "A"}, {name: "v"}, {name: "h", value: true}, {name: "j"}})
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	path := "/api/v1/alerts"
	if p.has("A") {
		path += "?all=1"
	}
	var rows []alertRow
	if err := c.getJSON(path, &rows); err != nil {
		return err
	}
	if h := listHospital(c, p.str("h")); h != "" {
		kept := rows[:0]
		for _, r := range rows {
			if r.HospitalID == h {
				kept = append(kept, r)
			}
		}
		rows = kept
	}
	if p.has("j") {
		return printJSON(rows)
	}
	fmt.Printf("%-6s %-20s %-10s %-22s %s\n", "ID", T("时间", "TIME"), T("类型", "KIND"), T("对象", "ASSET"), T("内容", "SUMMARY"))
	for _, r := range rows {
		kind := T("权限新增", "new-perms")
		sum := fmt.Sprintf(T("新增 %d 项", "%d added"), r.AddedCount)
		if r.Kind == "audit_failed" {
			kind, sum = T("复检失败", "audit-fail"), short(r.Error, 60)
		}
		if r.AckedAt != "" {
			sum += fmt.Sprintf(T("（已确认 %s）", " (acked by %s)"), r.AckedBy)
		}
		fmt.Printf("%-6d %-20s %-10s %-22s %s\n", r.ID, r.CreatedAt, kind, r.AssetID, sum)
		if p.has("v") {
			for _, it := range r.Items {
				fmt.Printf("         · %s %s %s\n", it.Category, it.Subject, it.Detail)
			}
		}
	}
	hint := ""
	if !p.has("A") {
		hint = T("（未确认；-A 含已确认，-v 看明细）", " (open; -A includes acked, -v shows items)")
	}
	fmt.Printf(T("共 %d 条告警%s\n", "%d alerts%s\n"), len(rows), hint)
	return nil
}

func cmdAlertAck(args []string) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	if err := p.requirePos(1, T("ma alertack <告警id…>", "ma alertack <alert-id...>")); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	for _, id := range p.pos {
		if _, err := strconv.ParseInt(id, 10, 64); err != nil {
			return fmt.Errorf(T("告警 id 应为数字：%s", "alert id must be a number: %s"), id)
		}
		if err := c.postJSON("/api/v1/alerts/"+id+"/ack", map[string]string{}, nil); err != nil {
			return err
		}
		fmt.Printf(T("告警 %s 已确认\n", "Alert %s acknowledged\n"), id)
	}
	return nil
}

func cmdAuditDue(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "h", value: true}, {name: "A"}, {name: "j"}})
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var res struct {
		CycleDays int `json:"cycle_days"`
		Items     []struct {
			AssetID     string `json:"asset_id"`
			HospitalID  string `json:"hospital_id"`
			Name        string `json:"name"`
			LastAuditAt string `json:"last_audit_at"`
			DaysLeft    int    `json:"days_left"`
			Status      string `json:"status"`
			Auto        bool   `json:"auto"`
		} `json:"items"`
	}
	if err := c.getJSON("/api/v1/audit/due", &res); err != nil {
		return err
	}
	h := listHospital(c, p.str("h"))
	if p.has("j") {
		return printJSON(res)
	}
	fmt.Printf("%-22s %-22s %-14s %-6s %s\n", T("对象", "ASSET"), T("上次审计", "LAST AUDIT"), T("状态", "STATUS"), T("自动", "AUTO"), T("名称", "NAME"))
	n := 0
	for _, d := range res.Items {
		if (h != "" && d.HospitalID != h) || (d.Status == "ok" && !p.has("A")) {
			continue
		}
		st := map[string]string{
			"overdue":  fmt.Sprintf(T("逾期 %d 天", "overdue %dd"), -d.DaysLeft),
			"never":    T("从未审计", "never"),
			"due_soon": fmt.Sprintf(T("%d 天后到期", "due in %dd"), d.DaysLeft),
			"ok":       fmt.Sprintf(T("%d 天后到期", "due in %dd"), d.DaysLeft),
		}[d.Status]
		auto := "-"
		if d.Auto {
			auto = T("是", "yes")
		}
		last := d.LastAuditAt
		if last == "" {
			last = "—"
		}
		fmt.Printf("%-22s %-22s %-14s %-6s %s\n", d.AssetID, last, st, auto, d.Name)
		n++
	}
	hint := ""
	if !p.has("A") {
		hint = T("（只列需处理的；-A 列全部）", " (needing action only; -A lists all)")
	}
	fmt.Printf(T("复检周期 %d 天；列出 %d 个对象%s\n", "Cycle %d days; %d assets listed%s\n"), res.CycleDays, n, hint)
	return nil
}

type scheduleRow struct {
	AssetID      string `json:"asset_id"`
	HospitalID   string `json:"hospital_id"`
	Name         string `json:"name"`
	CycleDays    int    `json:"cycle_days"`
	NextRunAt    string `json:"next_run_at"`
	LastRunAt    string `json:"last_run_at"`
	LastStatus   string `json:"last_status"`
	LastError    string `json:"last_error"`
	LastBundleID string `json:"last_bundle_id"`
}

func cmdScheduleList(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "h", value: true}, {name: "j"}})
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var res struct {
		Items    []scheduleRow `json:"items"`
		KeyReady bool          `json:"key_ready"`
	}
	if err := c.getJSON("/api/v1/schedules", &res); err != nil {
		return err
	}
	if p.has("j") {
		return printJSON(res)
	}
	h := listHospital(c, p.str("h"))
	fmt.Printf("%-22s %-6s %-22s %-8s %s\n", T("对象", "ASSET"), T("周期", "CYCLE"), T("下次执行", "NEXT RUN"), T("上次", "LAST"), T("说明", "NOTE"))
	n := 0
	for _, s := range res.Items {
		if h != "" && s.HospitalID != h {
			continue
		}
		last := map[string]string{"ok": T("成功", "ok"), "failed": T("失败", "failed"), "running": T("执行中", "running"), "": "—"}[s.LastStatus]
		note := s.LastBundleID
		if s.LastStatus == "failed" {
			note = short(s.LastError, 60)
		}
		fmt.Printf("%-22s %-6s %-22s %-8s %s\n", s.AssetID, fmt.Sprintf(T("%d天", "%dd"), s.CycleDays), s.NextRunAt, last, note)
		n++
	}
	fmt.Printf(T("共 %d 个对象开启定期自动复检\n", "%d assets have scheduled re-audits\n"), n)
	if !res.KeyReady {
		fmt.Println(T("注意：服务端未配置证据密钥，不能开启新的定期复检", "Note: the server has no evidence key; new schedules cannot be enabled"))
	}
	return nil
}

func cmdScheduleOn(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "d", value: true, def: "30"}, {name: "e", value: true}, {name: "k"}})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, T("ma schedon <资产id> [-d 天数] [-e 口令环境变量] [-k 沿用已存口令]", "ma schedon <asset-id> [-d days] [-e password-env] [-k keep stored password]")); err != nil {
		return err
	}
	days, err := strconv.Atoi(p.str("d"))
	if err != nil || days < 1 {
		return errors.New(T("-d 应为正整数天数", "-d must be a positive number of days"))
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	body := map[string]any{"cycle_days": days}
	if !p.has("k") {
		pw, err := auditPassword(p.str("e"), fmt.Sprintf(T("%s 的目标登录口令（加密保存，用于定期复检）: ", "Target login password for %s (stored encrypted for scheduled re-audits): "), p.pos[0]))
		if err != nil {
			return err
		}
		body["password"] = pw
	}
	if _, _, err := c.do("PUT", "/api/v1/schedules/"+escapePath(p.pos[0]), body); err != nil {
		return err
	}
	fmt.Printf(T("已开启：%s 每 %d 天自动复检（口令已加密保存；ma schedoff 关闭并删除口令）\n",
		"Enabled: %s re-audited every %d days (password stored encrypted; ma schedoff disables and deletes it)\n"), p.pos[0], days)
	return nil
}

func cmdScheduleOff(args []string) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	if err := p.requirePos(1, T("ma schedoff <资产id>", "ma schedoff <asset-id>")); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	if _, _, err := c.do("DELETE", "/api/v1/schedules/"+escapePath(p.pos[0]), nil); err != nil {
		return err
	}
	fmt.Printf(T("已关闭 %s 的定期自动复检，保存的口令已删除\n", "Scheduled re-audit of %s disabled; stored password deleted\n"), p.pos[0])
	return nil
}

func cmdScheduleRun(args []string) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	if err := p.requirePos(1, T("ma schedrun <资产id>", "ma schedrun <asset-id>")); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	if err := c.postJSON("/api/v1/schedules/"+escapePath(p.pos[0])+"/run", map[string]string{}, nil); err != nil {
		return err
	}
	fmt.Printf(T("已开始复检 %s（后台执行；ma schedls 查看结果）\n", "Re-audit of %s started (in background; see ma schedls)\n"), p.pos[0])
	return nil
}

func cmdOpLog(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "j"}})
	if err != nil {
		return err
	}
	limit := 30
	if len(p.pos) > 0 {
		if limit, err = strconv.Atoi(p.pos[0]); err != nil || limit < 1 {
			return errors.New(T("用法：ma oplog [条数]", "Usage: ma oplog [count]"))
		}
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var res struct {
		Total int `json:"total"`
		Items []struct {
			At       string `json:"at"`
			Actor    string `json:"actor"`
			Method   string `json:"method"`
			Path     string `json:"path"`
			Status   int    `json:"status"`
			ClientIP string `json:"client_ip"`
			Note     string `json:"note"`
		} `json:"items"`
	}
	if err := c.getJSON(fmt.Sprintf("/api/v1/admin/oplog?limit=%d", limit), &res); err != nil {
		return err
	}
	if p.has("j") {
		return printJSON(res)
	}
	fmt.Printf("%-21s %-12s %-6s %-4s %-15s %s\n", T("时间(UTC)", "TIME(UTC)"), T("操作人", "ACTOR"), T("方法", "METHOD"), T("结果", "CODE"), T("来源", "FROM"), T("请求", "REQUEST"))
	for _, e := range res.Items {
		req := e.Path
		if e.Note != "" {
			req += "  " + e.Note
		}
		fmt.Printf("%-21s %-12s %-6s %-4d %-15s %s\n", e.At, e.Actor, e.Method, e.Status, e.ClientIP, req)
	}
	fmt.Printf(T("显示 %d / 共 %d 条（ma oplogchk 校验完整性）\n", "Showing %d of %d (verify integrity with ma oplogchk)\n"), len(res.Items), res.Total)
	return nil
}

func cmdOpLogCheck(args []string) error {
	if _, err := parseArgs(args, nil); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var res struct {
		OK       bool  `json:"ok"`
		Rows     int   `json:"rows"`
		BrokenAt int64 `json:"broken_at"`
	}
	if err := c.getJSON("/api/v1/admin/oplog/verify", &res); err != nil {
		return err
	}
	if !res.OK {
		return &exitError{code: 2, msg: fmt.Sprintf(T("操作日志被改动：第 %d 条起记录不可信", "operation log tampered: records from #%d on cannot be trusted"), res.BrokenAt)}
	}
	fmt.Printf(T("操作日志完整：%d 条记录未被改动\n", "Operation log intact: %d records unchanged\n"), res.Rows)
	return nil
}

type templateRow struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	System      string `json:"system"`
	Target      string `json:"target"`
	Status      string `json:"status"`
	Description string `json:"description"`
	Entries     []struct {
		Subject string `json:"subject"`
		Kind    string `json:"kind"`
		Value   string `json:"value"`
		Scope   string `json:"scope"`
		Reason  string `json:"reason"`
	} `json:"entries"`
	Placeholders []string `json:"placeholders"`
	Source       string   `json:"source"`
}

func fetchTemplates(c *client) ([]templateRow, []string, error) {
	var res struct {
		Items  []templateRow `json:"items"`
		Errors []string      `json:"errors"`
	}
	if err := c.getJSON("/api/v1/baseline-templates", &res); err != nil {
		return nil, nil, err
	}
	return res.Items, res.Errors, nil
}

func cmdTemplateList(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "j"}})
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	rows, errs, err := fetchTemplates(c)
	if err != nil {
		return err
	}
	if p.has("j") {
		return printJSON(rows)
	}
	fmt.Printf("%-20s %-6s %-14s %-6s %-5s %s\n", T("模板", "TEMPLATE"), T("系统", "SYSTEM"), T("目标", "TARGET"), T("状态", "STATUS"), T("条数", "ITEMS"), T("名称", "NAME"))
	for _, t := range rows {
		st := T("已核实", "verified")
		if t.Status != "verified" {
			st = T("草稿", "draft")
		}
		fmt.Printf("%-20s %-6s %-14s %-6s %-5d %s\n", t.ID, t.System, t.Target, st, len(t.Entries), t.Name)
	}
	for _, e := range errs {
		fmt.Println(T("模板文件有误：", "Template file error: ") + e)
	}
	fmt.Println(T("ma tplshow <模板> 看条目；ma tpluse <模板> [占位=账号…] -b 基线 套用", "ma tplshow <template> lists items; ma tpluse <template> [placeholder=account...] -b baseline applies it"))
	return nil
}

func cmdTemplateShow(args []string) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	if err := p.requirePos(1, T("ma tplshow <模板id>", "ma tplshow <template-id>")); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	rows, _, err := fetchTemplates(c)
	if err != nil {
		return err
	}
	for _, t := range rows {
		if t.ID != p.pos[0] {
			continue
		}
		fmt.Printf("%s（%s · %s · %s）\n%s\n", t.Name, t.System, t.Target, t.Status, strings.TrimSpace(t.Description))
		for i, e := range t.Entries {
			sc := ""
			if e.Scope != "" {
				sc = " @" + e.Scope
			}
			fmt.Printf("  [%d] %s  %s=%s%s  —— %s\n", i, e.Subject, e.Kind, e.Value, sc, e.Reason)
		}
		if len(t.Placeholders) > 0 {
			fmt.Printf(T("套用时须填写：%s\n", "Must fill in when applying: %s\n"), strings.Join(t.Placeholders, " "))
		}
		return nil
	}
	return fmt.Errorf(T("模板 %s 不存在", "template %s not found"), p.pos[0])
}

func cmdTemplateApply(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "b", value: true}, {name: "h", value: true}, {name: "x", value: true}})
	if err != nil {
		return err
	}
	usage := T("ma tpluse <模板id> [{占位}=账号…] [-b 基线] [-x 跳过序号,序号] [-h 医院]", "ma tpluse <template-id> [{placeholder}=account...] [-b baseline] [-x skip-index,index] [-h hospital]")
	if err := p.requirePos(1, usage); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	hosp, err := c.contextHospital(p.str("h"))
	if err != nil {
		return err
	}
	values := map[string]string{}
	for _, kv := range p.pos[1:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("%s%s", T("用法：", "Usage: "), usage)
		}
		if !strings.HasPrefix(k, "{") {
			k = "{" + k + "}"
		}
		values[k] = v
	}
	skip := []int{}
	if x := p.str("x"); x != "" {
		for _, s := range strings.Split(x, ",") {
			i, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil {
				return errors.New(T("-x 应为逗号分隔的序号（见 ma tplshow）", "-x must be comma-separated indexes (see ma tplshow)"))
			}
			skip = append(skip, i)
		}
	}
	baseline := p.str("b")
	if baseline == "" {
		baseline = "bl-" + p.pos[0]
	}
	var res struct {
		BaselineID      string `json:"baseline_id"`
		Created         bool   `json:"created"`
		Added           int    `json:"added"`
		Reevaluated     int    `json:"reevaluated"`
		ReevaluateError string `json:"reevaluate_error"`
	}
	body := map[string]any{"hospital_id": hosp, "baseline_id": baseline, "values": values, "skip": skip}
	if err := c.postJSON("/api/v1/baseline-templates/"+escapePath(p.pos[0])+"/apply", body, &res); err != nil {
		return err
	}
	verb := T("已追加到", "appended to")
	if res.Created {
		verb = T("已新建", "created")
	}
	fmt.Printf(T("%s基线 %s：新增 %d 条放行项，已重评 %d 个对象的最新审计\n", "%s baseline %s: %d allows added, latest audit of %d assets re-evaluated\n"), verb, res.BaselineID, res.Added, res.Reevaluated)
	if res.ReevaluateError != "" {
		return errors.New(res.ReevaluateError)
	}
	return nil
}

func cmdCompliance(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "j"}})
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var res struct {
		Items []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Status  string `json:"status"`
			Source  string `json:"source"`
			Clauses int    `json:"clauses"`
			Enabled bool   `json:"enabled"`
		} `json:"items"`
		Errors []string `json:"errors"`
	}
	if err := c.getJSON("/api/v1/compliance/frameworks", &res); err != nil {
		return err
	}
	if p.has("j") {
		return printJSON(res)
	}
	fmt.Printf("%-16s %-6s %-8s %-8s %-6s %s\n", T("框架", "FRAMEWORK"), T("条款", "CLAUSES"), T("状态", "STATUS"), T("来源", "SOURCE"), T("报告", "REPORT"), T("名称", "NAME"))
	for _, f := range res.Items {
		on := T("未启用", "off")
		if f.Enabled {
			on = T("启用", "on")
		}
		fmt.Printf("%-16s %-6d %-8s %-8s %-6s %s\n", f.ID, f.Clauses, f.Status, f.Source, on, f.Name)
	}
	for _, e := range res.Errors {
		fmt.Println(T("框架文件有误：", "Framework file error: ") + e)
	}
	return nil
}
