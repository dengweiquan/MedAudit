package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ---------- 基线 ----------

func fetchBaselines(c *client, hospital string) ([]baselineRow, error) {
	var rows []baselineRow
	if err := c.getJSON("/api/v1/baselines?hospital_id="+escapePath(hospital), &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func rowToFile(r baselineRow) (*baselineFile, error) {
	var spec struct {
		Allows []baselineAllow `json:"allows"`
	}
	if err := json.Unmarshal([]byte(r.Spec), &spec); err != nil {
		return nil, fmt.Errorf("基线 %s 的 spec 解析失败: %w", r.ID, err)
	}
	return &baselineFile{ID: r.ID, HospitalID: r.HospitalID, Target: r.Target, Allows: spec.Allows}, nil
}

func cmdBaselineList(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "h", value: true}, {name: "j"}})
	if err != nil {
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
	rows, err := fetchBaselines(c, hosp)
	if err != nil {
		return err
	}
	if p.has("j") {
		return printJSON(rows)
	}
	fmt.Printf("%-28s %-18s %-14s %s\n", "基线", "医院", "目标", "放行条数")
	for _, r := range rows {
		bf, err := rowToFile(r)
		n := 0
		if err == nil {
			n = len(bf.Allows)
		}
		fmt.Printf("%-28s %-18s %-14s %d\n", r.ID, r.HospitalID, r.Target, n)
	}
	fmt.Printf("共 %d 条基线（医院 %s）\n", len(rows), hosp)
	return nil
}

func cmdBaselineGet(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "h", value: true}, {name: "o", value: true}})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, "mabaseshow <id> [-o 文件] [-h 医院]"); err != nil {
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
	rows, err := fetchBaselines(c, hosp)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.ID == p.pos[0] {
			bf, err := rowToFile(r)
			if err != nil {
				return err
			}
			raw, _ := json.MarshalIndent(bf, "", "  ")
			if p.str("o") != "" {
				if err := os.WriteFile(p.str("o"), raw, 0o644); err != nil {
					return err
				}
				fmt.Printf("基线 %s 已导出到 %s（%d 条放行）\n", r.ID, p.str("o"), len(bf.Allows))
				return nil
			}
			fmt.Println(string(raw))
			return nil
		}
	}
	return fmt.Errorf("基线 %s 不存在（医院 %s）", p.pos[0], hosp)
}

func cmdBaselineApply(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "f", value: true}, {name: "h", value: true}})
	if err != nil {
		return err
	}
	file := p.str("f")
	if file == "" && len(p.pos) > 0 {
		file = p.pos[0]
	}
	if file == "" {
		return fmt.Errorf("用法：mabaseadd -f 基线.json")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var bf baselineFile
	if err := json.Unmarshal(raw, &bf); err != nil {
		return fmt.Errorf("基线文件解析失败: %w", err)
	}
	if bf.ID == "" {
		return fmt.Errorf("基线文件缺 id")
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	if bf.HospitalID == "" {
		hosp, err := c.contextHospital(p.str("h"))
		if err != nil {
			return err
		}
		bf.HospitalID = hosp
	}
	if bf.CreatedBy == "" {
		bf.CreatedBy = c.username()
	}
	var out map[string]any
	if err := c.postJSON("/api/v1/baselines", bf, &out); err != nil {
		return err
	}
	fmt.Printf("基线 %s 已登记（%d 条放行）\n", bf.ID, len(bf.Allows))
	return nil
}

func loadBaselineSource(c *client, src, hospital string) (*baselineFile, error) {
	if strings.HasSuffix(src, ".json") {
		raw, err := os.ReadFile(src)
		if err != nil {
			return nil, err
		}
		var bf baselineFile
		if err := json.Unmarshal(raw, &bf); err != nil {
			return nil, fmt.Errorf("%s 解析失败: %w", src, err)
		}
		return &bf, nil
	}
	rows, err := fetchBaselines(c, hospital)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.ID == src {
			return rowToFile(r)
		}
	}
	return nil, fmt.Errorf("基线 %s 不存在（医院 %s）", src, hospital)
}

func allowKey(a baselineAllow) string {
	return a.Subject + "|" + a.Kind + "|" + a.Value + "|" + a.Scope
}

func cmdBaselineDiff(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "h", value: true}})
	if err != nil {
		return err
	}
	if err := p.requirePos(2, "mabasediff <基线A> <基线B>（ID 或 .json 文件）"); err != nil {
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
	fa, err := loadBaselineSource(c, p.pos[0], hosp)
	if err != nil {
		return err
	}
	fb, err := loadBaselineSource(c, p.pos[1], hosp)
	if err != nil {
		return err
	}
	setA := map[string]baselineAllow{}
	for _, x := range fa.Allows {
		setA[allowKey(x)] = x
	}
	setB := map[string]baselineAllow{}
	for _, x := range fb.Allows {
		setB[allowKey(x)] = x
	}
	fmt.Printf("基线差异 %s（%d 条）→ %s（%d 条）\n", fa.ID, len(fa.Allows), fb.ID, len(fb.Allows))
	only := 0
	for k, x := range setB {
		if _, ok := setA[k]; !ok {
			fmt.Printf("  + %s · %s · %s（%s）\n", x.Subject, x.Kind, x.Value, x.Scope)
			only++
		}
	}
	for k, x := range setA {
		if _, ok := setB[k]; !ok {
			fmt.Printf("  - %s · %s · %s（%s）\n", x.Subject, x.Kind, x.Value, x.Scope)
			only++
		}
	}
	if only == 0 {
		fmt.Println("  无差异")
	}
	return nil
}

// ---------- 一键豁免（M22 接口的 CLI 版） ----------

type exemptionPreview struct {
	Supported  bool            `json:"supported"`
	RuleID     string          `json:"rule_id"`
	Subject    string          `json:"subject"`
	Target     string          `json:"target"`
	HospitalID string          `json:"hospital_id"`
	Allows     []baselineAllow `json:"allows"`
}

func cmdBaselineExempt(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "b", value: true}, {name: "y"}})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, "mabaseexempt <finding-id> [-b 基线] [-y] [原因…]"); err != nil {
		return err
	}
	findingID, err := strconv.ParseInt(p.pos[0], 10, 64)
	if err != nil {
		return fmt.Errorf("finding-id 须为数字（问题清单 mafind 输出的 id）")
	}
	reason := strings.Join(p.pos[1:], " ")
	c, err := newClient()
	if err != nil {
		return err
	}
	var pv exemptionPreview
	if err := c.postJSON("/api/v1/baselines/exempt-preview", map[string]any{"finding_id": findingID}, &pv); err != nil {
		return err
	}
	if !pv.Supported {
		return fmt.Errorf("规则 %s 不支持基线豁免（可使用 maruleoff 整类关闭）", pv.RuleID)
	}
	fmt.Printf("问题：%s · %s\n将加入的放行项（按证据推导）：\n", pv.RuleID, pv.Subject)
	for _, a := range pv.Allows {
		fmt.Printf("  %s · %s = %s（scope %q）\n", a.Subject, a.Kind, a.Value, a.Scope)
	}
	// 目标基线：-b 指定（存在则追加、不存在则新建）；缺省时唯一匹配自动选、无匹配则新建
	baselineID, newID := "", ""
	rows, err := fetchBaselines(c, pv.HospitalID)
	if err != nil {
		return err
	}
	exists := map[string]bool{}
	var matching []string
	for _, r := range rows {
		exists[r.ID] = true
		if r.Target == pv.Target {
			matching = append(matching, r.ID)
		}
	}
	if p.str("b") != "" {
		if exists[p.str("b")] {
			baselineID = p.str("b")
		} else {
			newID = p.str("b")
		}
	} else if len(matching) == 1 {
		baselineID = matching[0]
	} else if len(matching) > 1 {
		return fmt.Errorf("该目标有多条基线（%s）：用 -b 指定一条", strings.Join(matching, "、"))
	} else {
		newID = "bl-exempt-" + pv.Target
	}
	target := baselineID
	if target == "" {
		target = newID + "（新建）"
	}
	fmt.Printf("目标基线：%s（医院 %s · 目标 %s）\n", target, pv.HospitalID, pv.Target)
	if !p.has("y") {
		fmt.Fprint(os.Stderr, "确认加入？[y/N] ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		line = strings.ToLower(strings.TrimSpace(line))
		if line != "y" && line != "yes" {
			fmt.Println("已取消")
			return nil
		}
	}
	body := map[string]any{"finding_id": findingID, "reason": reason, "created_by": c.username()}
	if baselineID != "" {
		body["baseline_id"] = baselineID
	} else {
		body["new_baseline_id"] = newID
	}
	var res struct {
		BaselineID string          `json:"baseline_id"`
		Added      []baselineAllow `json:"added"`
		Skipped    int             `json:"skipped_existing"`
	}
	if err := c.postJSON("/api/v1/baselines/exempt", body, &res); err != nil {
		return err
	}
	fmt.Printf("已加入基线 %s（新增 %d 条", res.BaselineID, len(res.Added))
	if res.Skipped > 0 {
		fmt.Printf("，%d 条已存在跳过", res.Skipped)
	}
	fmt.Println("）。用该基线重新评估（maeval -b）后生效。")
	return nil
}

// ---------- 规则启停 ----------

func cmdRuleList(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "j"}})
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var rules []ruleSpecRow
	if err := c.getJSON("/api/v1/rules", &rules); err != nil {
		return err
	}
	var toggles []ruleToggleRow
	if err := c.getJSON("/api/v1/rule-toggles", &toggles); err != nil {
		return err
	}
	off := map[string]ruleToggleRow{}
	for _, t := range toggles {
		if !t.Enabled {
			off[t.RuleID] = t
		}
	}
	if p.has("j") {
		return printJSON(map[string]any{"rules": rules, "disabled": toggles})
	}
	fmt.Printf("%-38s %-10s %-8s %s\n", "规则", "目标", "状态", "关闭原因（留痕）")
	for _, r := range rules {
		st := "启用"
		note := ""
		if t, ok := off[r.ID]; ok {
			st = "已关闭"
			note = fmt.Sprintf("%s（%s · %s）", t.Reason, t.UpdatedBy, t.UpdatedAt)
		}
		fmt.Printf("%-38s %-10s %-8s %s\n", r.ID, r.Target, st, note)
	}
	fmt.Printf("共 %d 条规则，已关闭 %d 条\n", len(rules), len(off))
	return nil
}

func cmdRuleSet(args []string, enabled bool) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	if enabled {
		if err := p.requirePos(1, "maruleon <规则id>"); err != nil {
			return err
		}
	} else if err := p.requirePos(2, "maruleoff <规则id> <原因…>"); err != nil {
		return err
	}
	id := p.pos[0]
	reason := strings.Join(p.pos[1:], " ")
	c, err := newClient()
	if err != nil {
		return err
	}
	body := map[string]any{"rule_id": id, "enabled": enabled, "reason": reason, "updated_by": c.username()}
	if _, _, err := c.do("PUT", "/api/v1/rule-toggles", body); err != nil {
		return err
	}
	if enabled {
		fmt.Printf("规则 %s 已开启\n", id)
	} else {
		fmt.Printf("规则 %s 已关闭（本站）：新评估将跳过该项，报告不体现\n", id)
	}
	return nil
}
