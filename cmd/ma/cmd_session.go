package main

import (
	"fmt"
	"os"
)

// ---------- 会话与上下文 ----------

func cmdLogin(args []string) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	user := ""
	if len(p.pos) > 0 {
		user = p.pos[0]
	}
	if user == "" {
		user = os.Getenv("MEDAUDIT_USER")
	}
	if user == "" {
		user = "admin"
	}
	c := &client{base: serverBase(), hc: httpClient()}
	pass := os.Getenv("MEDAUDIT_PASS")
	if pass == "" {
		pw, err := readPassword(fmt.Sprintf("%s 的口令: ", user))
		if err != nil {
			return err
		}
		pass = pw
	}
	if err := c.login(user, pass); err != nil {
		return err
	}
	fmt.Printf("已登录 %s（服务端 %s，会话存 ~/.medaudit/session.json）\n", user, c.base)
	return nil
}

func cmdLogout(args []string) error {
	c, err := newClient()
	if err == nil && c.cookie != "" {
		_, _, _ = c.do("POST", "/api/v1/auth/logout", map[string]string{})
	}
	clearSession()
	fmt.Println("已注销并清除本地会话")
	return nil
}

func cmdWhoami(args []string) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	u := c.username()
	if u == "" {
		return fmt.Errorf("未登录或会话已过期：先运行 malogin")
	}
	hosp := ""
	if s, err := loadSession(); err == nil {
		hosp = s.Hospital
	}
	src := "本站（服务端给定）"
	if hosp == "" {
		hosp = c.siteHospitalID()
		if hosp == "" {
			hosp = "（未设定，多院实例请 mause 指定）"
			src = ""
		}
	} else {
		src = "mause 设定"
	}
	fmt.Printf("%s @ %s\n当前医院：%s %s\n", u, c.base, hosp, src)
	return nil
}

func cmdUse(args []string) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	if len(p.pos) == 0 {
		return cmdWhoami(nil)
	}
	if err := setContextHospital(p.pos[0]); err != nil {
		return err
	}
	fmt.Printf("当前医院上下文已设为 %s\n", p.pos[0])
	return nil
}

func cmdSite(args []string) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	var site struct {
		HospitalID string `json:"hospital_id"`
		Name       string `json:"name"`
	}
	if err := c.getJSON("/api/v1/site", &site); err != nil {
		return err
	}
	if site.HospitalID == "" {
		fmt.Println("本站未初始化（多院/开发模式）：用 mause <医院ID> 设定当前医院上下文")
		return nil
	}
	fmt.Printf("本站医院：%s（%s）\n", site.HospitalID, site.Name)
	return nil
}

// ---------- 平台账号 ----------

func cmdUserList(args []string) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	var rows []userRow
	if err := c.getJSON("/api/v1/users", &rows); err != nil {
		return err
	}
	fmt.Printf("%-24s %-8s %-10s %s\n", "用户名", "状态", "强制改密", "创建时间")
	for _, u := range rows {
		st := "正常"
		if u.Disabled {
			st = "已禁用"
		}
		mc := "否"
		if u.MustChangePwd {
			mc = "是"
		}
		fmt.Printf("%-24s %-8s %-10s %s\n", u.Username, st, mc, u.CreatedAt)
	}
	fmt.Printf("共 %d 个用户\n", len(rows))
	return nil
}

func cmdUserAdd(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "e", value: true}})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, "mauseradd <name> [-e 口令环境变量]"); err != nil {
		return err
	}
	name := p.pos[0]
	pw, err := userPassword(p.str("e"), fmt.Sprintf("新用户 %s 的初始口令: ", name))
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var out map[string]any
	if err := c.postJSON("/api/v1/users", map[string]string{"username": name, "password": pw}, &out); err != nil {
		return err
	}
	fmt.Printf("用户 %s 已创建（首登强制改密）\n", name)
	return nil
}

func cmdUserPassword(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "e", value: true}})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, "mauserpw <name> [-e 口令环境变量]"); err != nil {
		return err
	}
	name := p.pos[0]
	pw, err := userPassword(p.str("e"), fmt.Sprintf("用户 %s 的新口令: ", name))
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	if _, _, err := c.do("PUT", "/api/v1/users/"+escapePath(name)+"/password", map[string]string{"password": pw}); err != nil {
		return err
	}
	fmt.Printf("用户 %s 的口令已重置（其全部会话已吊销，首登强制改密）\n", name)
	return nil
}

func cmdUserDisabled(args []string, disabled bool) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	verb := "mauseron"
	if disabled {
		verb = "mauseroff"
	}
	if err := p.requirePos(1, verb+" <name>"); err != nil {
		return err
	}
	name := p.pos[0]
	c, err := newClient()
	if err != nil {
		return err
	}
	if _, _, err := c.do("PUT", "/api/v1/users/"+escapePath(name)+"/disabled", map[string]bool{"disabled": disabled}); err != nil {
		return err
	}
	if disabled {
		fmt.Printf("用户 %s 已禁用（其全部会话已吊销）\n", name)
	} else {
		fmt.Printf("用户 %s 已启用\n", name)
	}
	return nil
}
