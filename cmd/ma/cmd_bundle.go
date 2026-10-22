package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

// ---------- 事实包 ----------

func cmdBundleList(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "a", value: true}, {name: "j"}})
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	rows, err := fetchBundles(c)
	if err != nil {
		return err
	}
	var out []bundleSummary
	for _, b := range rows {
		if p.str("a") == "" || b.AssetID == p.str("a") {
			out = append(out, b)
		}
	}
	if p.has("j") {
		return printJSON(out)
	}
	fmt.Printf("%-38s %-12s %-18s %-12s %-9s %s\n", "BUNDLE", "医院", "资产", "适配器", "执行", "事实数")
	for _, b := range out {
		fmt.Printf("%-38s %-12s %-18s %-12s %-9s %d\n", b.ID, b.HospitalID, b.AssetID, b.Adapter, b.Execution, b.FactCount)
	}
	fmt.Printf("共 %d 个事实包\n", len(out))
	return nil
}

func cmdBundleImport(args []string) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	if err := p.requirePos(1, "mabundlein <文件.zip>"); err != nil {
		return err
	}
	raw, err := os.ReadFile(p.pos[0])
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	// 机器通道：POST /bundles 直接传 zip（免登录会话亦可，带会话同样接受）
	status, respBody, err := c.doZip("/api/v1/bundles", raw)
	if err != nil {
		return err
	}
	var out map[string]any
	_ = json.Unmarshal(respBody, &out)
	fmt.Printf("导入结果 %d：%v\n", status, out)
	return nil
}

func cmdBundleShow(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "j"}})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, "mabundleshow <包id> [-j]"); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var d bundleDetail
	if err := c.getJSON("/api/v1/bundles/"+escapePath(p.pos[0]), &d); err != nil {
		return err
	}
	if p.has("j") {
		return printJSON(d)
	}
	fmt.Printf("事实包 %s\n  医院 %s · 方案 %s · 资产 %s · 适配器 %s（采集器 %s）\n  执行 %s · 导入 %s · 事实 %d 条\n",
		d.ID, d.HospitalID, d.PlanID, d.AssetID, d.Adapter, d.CollectorVersion, d.Execution, d.ImportedAt, d.FactCount)
	kinds := make([]string, 0, len(d.CountsByKind))
	for k := range d.CountsByKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		parts = append(parts, fmt.Sprintf("%s %d", k, d.CountsByKind[k]))
	}
	fmt.Printf("  事实构成：%s\n", strings.Join(parts, " · "))
	fmt.Printf("  收据 %d 张：\n", len(d.Receipts))
	for _, r := range d.Receipts {
		extra := ""
		if r.Truncated {
			extra += " [截断]"
		}
		if r.ErrorStage != "" {
			extra += " [阶段 " + r.ErrorStage + "]"
		}
		fmt.Printf("    %-28s %-8s %6d 行%s\n", r.TemplateID, r.Status, r.RowCount, extra)
	}
	return nil
}

func cmdBundleDrift(args []string) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	if err := p.requirePos(2, "mabundledrift <新包> <旧包>"); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var rep struct {
		BaseID       string `json:"base_id"`
		CompareID    string `json:"compare_id"`
		AddedTotal   int    `json:"added_total"`
		RemovedTotal int    `json:"removed_total"`
		Attention    int    `json:"attention"`
		Added        []struct {
			Category string `json:"category"`
			Subject  string `json:"subject"`
			Detail   string `json:"detail"`
		} `json:"added"`
		Removed []struct {
			Category string `json:"category"`
			Subject  string `json:"subject"`
			Detail   string `json:"detail"`
		} `json:"removed"`
	}
	path := fmt.Sprintf("/api/v1/bundles/%s/drift?against=%s", url.PathEscape(p.pos[0]), url.QueryEscape(p.pos[1]))
	if err := c.getJSON(path, &rep); err != nil {
		return err
	}
	fmt.Printf("漂移 %s 相对 %s：新增 %d、消失 %d，其中新增授权/角色关系 %d 项需关注\n",
		rep.CompareID, rep.BaseID, rep.AddedTotal, rep.RemovedTotal, rep.Attention)
	for _, it := range rep.Added {
		fmt.Printf("  + [%s] %s — %s\n", it.Category, it.Subject, it.Detail)
	}
	for _, it := range rep.Removed {
		fmt.Printf("  - [%s] %s — %s\n", it.Category, it.Subject, it.Detail)
	}
	return nil
}

func cmdBundleEffective(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "j"}})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, "mabundleeff <包id> [-j]"); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var rows []struct {
		Subject string `json:"subject"`
		IsRole  bool   `json:"is_role"`
		Roles   []struct {
			Role string   `json:"role"`
			Path []string `json:"path"`
		} `json:"roles"`
		Privileges []struct {
			Privilege string   `json:"privilege"`
			Direct    bool     `direct`
			Via       []string `json:"via"`
		} `json:"privileges"`
	}
	if err := c.getJSON("/api/v1/bundles/"+escapePath(p.pos[0])+"/effective", &rows); err != nil {
		return err
	}
	if p.has("j") {
		return printJSON(rows)
	}
	for _, e := range rows {
		kind := "主体"
		if e.IsRole {
			kind = "角色"
		}
		fmt.Printf("%s（%s）：有效角色 %d，有效权限 %d\n", e.Subject, kind, len(e.Roles), len(e.Privileges))
		for _, pr := range e.Privileges {
			if !pr.Direct {
				fmt.Printf("    派生权限 %s（经 %s）\n", pr.Privilege, strings.Join(pr.Via, " → "))
			}
		}
	}
	return nil
}
