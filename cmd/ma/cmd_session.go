package main

import (
	"errors"
	"fmt"
	"os"
)

// ---------- 会话与上下文 ----------

func cmdLogin(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "t", value: true}})
	if err != nil {
		return err
	}
	c := &client{base: serverBase(), hc: httpClient()}
	// M32：令牌登录优先（-t 优先于环境变量；令牌恒为 admin；建议走环境变量，避免进 shell 历史）。
	if tok := p.vals["t"]; tok != "" {
		if err := c.loginToken(tok); err != nil {
			return err
		}
		fmt.Printf(T("已登录 admin（令牌，服务端 %s，会话存 ~/.medaudit/session.json）\n", "Logged in as admin (token, server %s, session stored in ~/.medaudit/session.json)\n"), c.base)
		return nil
	}
	if tok := os.Getenv("MEDAUDIT_TOKEN"); tok != "" {
		if err := c.loginToken(tok); err != nil {
			return err
		}
		fmt.Printf(T("已登录 admin（令牌，服务端 %s，会话存 ~/.medaudit/session.json）\n", "Logged in as admin (token, server %s, session stored in ~/.medaudit/session.json)\n"), c.base)
		return nil
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
	pass := os.Getenv("MEDAUDIT_PASS")
	if pass == "" {
		pw, err := readPassword(fmt.Sprintf(T("%s 的口令: ", "Password for %s: "), user))
		if err != nil {
			return err
		}
		pass = pw
	}
	if err := c.login(user, pass); err != nil {
		return err
	}
	fmt.Printf(T("已登录 %s（服务端 %s，会话存 ~/.medaudit/session.json）\n", "Logged in as %s (server %s, session stored in ~/.medaudit/session.json)\n"), user, c.base)
	return nil
}

func cmdLogout(args []string) error {
	c, err := newClient()
	if err == nil && c.cookie != "" {
		_, _, _ = c.do("POST", "/api/v1/auth/logout", map[string]string{})
	}
	clearSession()
	fmt.Println(T("已注销并清除本地会话", "Logged out and local session cleared"))
	return nil
}

func cmdWhoami(args []string) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	u := c.username()
	if u == "" {
		return errors.New(T("未登录或会话已过期：先运行 ma login", "not logged in or session expired: run ma login first"))
	}
	hosp := ""
	if s, err := loadSession(); err == nil {
		hosp = s.Hospital
	}
	src := T("本站（服务端给定）", "site hospital (set by the server)")
	if hosp == "" {
		hosp = c.siteHospitalID()
		if hosp == "" {
			hosp = T("（未设定，多院实例请 ma use 指定）", "(not set; on multi-hospital instances use ma use)")
			src = ""
		}
	} else {
		src = T("ma use 设定", "set by ma use")
	}
	fmt.Printf(T("%s @ %s\n当前医院：%s %s\n", "%s @ %s\nCurrent hospital: %s %s\n"), u, c.base, hosp, src)
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
	fmt.Printf(T("当前医院上下文已设为 %s\n", "Current hospital context set to %s\n"), p.pos[0])
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
		fmt.Println(T("本站未初始化（多院/开发模式）：用 ma use <医院ID> 设定当前医院上下文", "Site not initialized (multi-hospital/dev mode): set the current hospital context with ma use <hospital-id>"))
		return nil
	}
	fmt.Printf(T("本站医院：%s（%s）\n", "Site hospital: %s (%s)\n"), site.HospitalID, site.Name)
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
	fmt.Printf("%-24s %-8s %-10s %s\n", T("用户名", "USERNAME"), T("状态", "STATUS"), T("强制改密", "MUST CHANGE"), T("创建时间", "CREATED"))
	for _, u := range rows {
		st := T("正常", "active")
		if u.Disabled {
			st = T("已禁用", "disabled")
		}
		mc := T("否", "no")
		if u.MustChangePwd {
			mc = T("是", "yes")
		}
		fmt.Printf("%-24s %-8s %-10s %s\n", u.Username, st, mc, u.CreatedAt)
	}
	fmt.Printf(T("共 %d 个用户\n", "%d users in total\n"), len(rows))
	return nil
}

func cmdUserAdd(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "e", value: true}})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, T("ma useradd <name> [-e 口令环境变量]", "ma useradd <name> [-e password-env]")); err != nil {
		return err
	}
	name := p.pos[0]
	pw, err := userPassword(p.str("e"), fmt.Sprintf(T("新用户 %s 的初始口令: ", "Initial password for new user %s: "), name))
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
	fmt.Printf(T("用户 %s 已创建（首登强制改密）\n", "User %s created (must change password at first login)\n"), name)
	return nil
}

func cmdUserPassword(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "e", value: true}})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, T("ma userpw <name> [-e 口令环境变量]", "ma userpw <name> [-e password-env]")); err != nil {
		return err
	}
	name := p.pos[0]
	pw, err := userPassword(p.str("e"), fmt.Sprintf(T("用户 %s 的新口令: ", "New password for user %s: "), name))
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
	fmt.Printf(T("用户 %s 的口令已重置（其全部会话已吊销，首登强制改密）\n", "Password for user %s reset (all its sessions revoked; must change at first login)\n"), name)
	return nil
}

func cmdUserDisabled(args []string, disabled bool) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	verb := "ma useron"
	if disabled {
		verb = "ma useroff"
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
		fmt.Printf(T("用户 %s 已禁用（其全部会话已吊销）\n", "User %s disabled (all its sessions revoked)\n"), name)
	} else {
		fmt.Printf(T("用户 %s 已启用\n", "User %s enabled\n"), name)
	}
	return nil
}
