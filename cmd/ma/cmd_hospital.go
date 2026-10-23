package main

import (
	"fmt"
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
	fmt.Printf("%-24s %-32s %s\n", "医院ID", "名称", "登记时间")
	for _, h := range rows {
		fmt.Printf("%-24s %-32s %s\n", h.ID, h.Name, h.CreatedAt)
	}
	fmt.Printf("共 %d 家医院\n", len(rows))
	return nil
}

func cmdHospitalAdd(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "n", value: true}})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, "ma hosadd <id> [-n 名称]"); err != nil {
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
	fmt.Printf("医院 %s（%s）已登记\n", id, name)
	return nil
}
