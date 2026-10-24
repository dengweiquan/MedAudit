package main

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ---------- 超级令牌管理（M32；铸造只经 ma CLI） ----------

func cmdToken(args []string) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	_ = p
	c, err := newClient()
	if err != nil {
		return errors.New(T("未登录或会话已过期：先运行 ma login", "not logged in or session expired: run ma login first"))
	}
	_, raw, err := c.do("POST", "/api/v1/auth/token", map[string]string{})
	if err != nil {
		return err
	}
	var res struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &res); err != nil || res.Token == "" {
		return errors.New(T("服务端未返回令牌", "server did not return a token"))
	}
	fmt.Println(T("超级令牌（只显示一次，请立即妥善保存；轮换后旧令牌立即失效，admin 全部会话已吊销）：",
		"Super token (shown only once — save it now; the old token is invalid immediately and all admin sessions are revoked):"))
	fmt.Println(res.Token)
	fmt.Println(T("登录用法：ma login -t <令牌>，或设置环境变量 MEDAUDIT_TOKEN；Web 登录页选“令牌登录”。",
		"Log in with: ma login -t <token>, or set MEDAUDIT_TOKEN; on the Web login page choose token login."))
	return nil
}

func cmdTokenOff(args []string) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	_ = p
	c, err := newClient()
	if err != nil {
		return errors.New(T("未登录或会话已过期：先运行 ma login", "not logged in or session expired: run ma login first"))
	}
	if _, _, err := c.do("POST", "/api/v1/auth/token/disable", map[string]string{}); err != nil {
		return err
	}
	fmt.Println(T("超级令牌已停用（之后令牌登录被拒；admin 全部会话已吊销；可用 ma token 重新生成）",
		"Super token disabled (token logins rejected afterwards; admin sessions revoked; run ma token to generate a new one)"))
	return nil
}
