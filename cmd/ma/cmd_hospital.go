package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ---------- 医院（客户）登记 ----------

// hospitalRow 医院登记行（与服务端 platform.Hospital 对齐）。
type hospitalRow struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

func cmdHospitalList(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "j"}})
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var rows []hospitalRow
	if err := c.getJSON("/api/v1/hospitals", &rows); err != nil {
		return err
	}
	if p.has("j") {
		return printJSON(rows)
	}
	fmt.Printf("%-24s %-32s %s\n", T("医院ID", "HOSPITAL ID"), T("名称", "NAME"), T("登记时间", "REGISTERED"))
	for _, h := range rows {
		fmt.Printf("%-24s %-32s %s\n", h.ID, h.Name, h.CreatedAt)
	}
	fmt.Printf(T("共 %d 家医院\n", "%d hospitals in total\n"), len(rows))
	return nil
}

func cmdHospitalAdd(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "n", value: true}})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, T("ma hosadd <id> [-n 名称]", "ma hosadd <id> [-n name]")); err != nil {
		return err
	}
	id := p.pos[0]
	name := p.str("n")
	if name == "" {
		name = id
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var out map[string]any
	if err := c.postJSON("/api/v1/hospitals", map[string]string{"id": id, "name": name}, &out); err != nil {
		return err
	}
	fmt.Printf(T("医院 %s（%s）已登记\n", "Hospital %s (%s) registered\n"), id, name)
	return nil
}

func cmdHospitalDelete(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "y"}})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, "ma hosrm <id> [-y]"); err != nil {
		return err
	}
	id := p.pos[0]
	c, err := newClient()
	if err != nil {
		return err
	}
	var detail struct {
		ID     string           `json:"id"`
		Name   string           `json:"name"`
		Counts map[string]int64 `json:"counts"`
	}
	if err := c.getJSON("/api/v1/hospitals/"+escapePath(id), &detail); err != nil {
		return err
	}
	fmt.Printf(T("将删除医院 %s（%s）及其全部数据：资产 %d、事实包 %d、问题 %d、报告 %d、基线 %d。\n", "About to delete hospital %s (%s) and ALL its data: %d assets, %d bundles, %d findings, %d reports, %d baselines.\n"),
		detail.ID, detail.Name, detail.Counts["assets"], detail.Counts["fact_bundles"],
		detail.Counts["findings"], detail.Counts["reports"]+detail.Counts["correlation_reports"],
		detail.Counts["baselines"])
	fmt.Println(T("此操作不可恢复（建议先 ma srvbak 备份）。", "This cannot be undone (back up first with ma srvbak)."))
	if !p.has("y") {
		fmt.Fprintf(os.Stderr, T("确认删除？输入医院 ID %s 继续：", "Confirm deletion: type the hospital ID %s to continue: "), id)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(line) != id {
			fmt.Println(T("已取消", "Cancelled"))
			return nil
		}
	}
	_, raw, err := c.do("DELETE", "/api/v1/hospitals/"+escapePath(id), nil)
	if err != nil {
		return err
	}
	var out struct {
		Deleted map[string]int64 `json:"deleted"`
	}
	if err := jsonUnmarshal(raw, &out); err != nil {
		return err
	}
	var total int64
	for _, n := range out.Deleted {
		total += n
	}
	fmt.Printf(T("医院 %s 已删除（共 %d 行）。\n", "Hospital %s deleted (%d rows in total).\n"), id, total)
	if s, err := loadSession(); err == nil && s.Hospital == id {
		_ = setContextHospital("")
		fmt.Println(T("当前医院上下文已清除（所删医院正是当前上下文）。", "Current hospital context cleared (the deleted hospital was the current context)."))
	}
	return nil
}
