package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// ---------- 会话与上下文（~/.medaudit/session.json，0600） ----------

type sessionFile struct {
	Server   string `json:"server"`
	Username string `json:"username"`
	Cookie   string `json:"cookie"`
	Hospital string `json:"hospital,omitempty"` // ma use 设定的当前医院上下文
}

func sessionDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".medaudit")
}

func loadSession() (*sessionFile, error) {
	raw, err := os.ReadFile(filepath.Join(sessionDir(), "session.json"))
	if err != nil {
		return nil, err
	}
	var s sessionFile
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func saveSession(s *sessionFile) error {
	dir := sessionDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, _ := json.Marshal(s)
	return os.WriteFile(filepath.Join(dir, "session.json"), raw, 0o600)
}

func clearSession() {
	_ = os.Remove(filepath.Join(sessionDir(), "session.json"))
}

// setContextHospital 更新会话中的当前医院（保留其余字段）。
func setContextHospital(h string) error {
	s, err := loadSession()
	if err != nil {
		return errors.New(T("尚无会话：先 ma login", "no session yet: run ma login first"))
	}
	s.Hospital = h
	return saveSession(s)
}

// ---------- HTTP 客户端 ----------

func httpClient() *http.Client { return &http.Client{Timeout: 10 * time.Minute} }

type client struct {
	base   string
	cookie string
	hc     *http.Client
}

func serverBase() string {
	if flagServer != "" {
		return strings.TrimRight(flagServer, "/")
	}
	if v := os.Getenv("MEDAUDIT_SERVER"); v != "" {
		return strings.TrimRight(v, "/")
	}
	if s, err := loadSession(); err == nil && s.Server != "" {
		return strings.TrimRight(s.Server, "/")
	}
	return "http://127.0.0.1:8080"
}

func newClient() (*client, error) {
	base := serverBase()
	c := &client{base: base, hc: &http.Client{Timeout: 10 * time.Minute}}
	if s, err := loadSession(); err == nil && s.Server == base && s.Cookie != "" {
		c.cookie = s.Cookie
		return c, nil
	}
	if u, p := os.Getenv("MEDAUDIT_USER"), os.Getenv("MEDAUDIT_PASS"); u != "" && p != "" {
		if err := c.login(u, p); err != nil {
			return nil, fmt.Errorf(T("环境变量凭据自动登录失败: %w", "auto-login with environment credentials failed: %w"), err)
		}
		return c, nil
	}
	return c, nil
}

func (c *client) do(method, path string, body any) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: "medaudit_session", Value: c.cookie})
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized && !strings.HasSuffix(path, "/auth/login") {
		return resp.StatusCode, raw, fmt.Errorf(T("未登录或会话已过期：先运行 ma login（%s）", "not logged in or session expired: run ma login first (%s)"), c.base)
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, raw, fmt.Errorf("%s %s -> %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return resp.StatusCode, raw, nil
}

// doZip 上传 zip 原始字节（事实包导入通道）。
func (c *client) doZip(path string, raw []byte) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/zip")
	if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: "medaudit_session", Value: c.cookie})
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return resp.StatusCode, body, fmt.Errorf("POST %s -> %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return resp.StatusCode, body, nil
}

func (c *client) getJSON(path string, out any) error {
	_, raw, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (c *client) postJSON(path string, body, out any) error {
	_, raw, err := c.do(http.MethodPost, path, body)
	if err != nil {
		return err
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (c *client) login(user, pass string) error {
	raw, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	req, err := http.NewRequest(http.MethodPost, c.base+"/api/v1/auth/login", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(T("登录失败 %d: %s", "login failed %d: %s"), resp.StatusCode, strings.TrimSpace(string(body)))
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == "medaudit_session" {
			c.cookie = ck.Value
			s := &sessionFile{Server: c.base, Username: user, Cookie: ck.Value}
			if old, err := loadSession(); err == nil && old.Server == c.base {
				s.Hospital = old.Hospital // 同服务端重登录保留医院上下文
			}
			return saveSession(s)
		}
	}
	return errors.New(T("登录响应未包含会话 Cookie", "login response did not include a session cookie"))
}

func (c *client) username() string {
	var me struct {
		Username string `json:"username"`
	}
	if err := c.getJSON("/api/v1/auth/me", &me); err != nil {
		return ""
	}
	return me.Username
}

// ---------- 上下文医院 ----------

var siteOnce sync.Once
var siteHospital string

// siteHospitalID 查本站医院（GET /api/v1/site），进程内缓存。
func (c *client) siteHospitalID() string {
	siteOnce.Do(func() {
		var site struct {
			HospitalID string `json:"hospital_id"`
		}
		if err := c.getJSON("/api/v1/site", &site); err == nil {
			siteHospital = site.HospitalID
		}
	})
	return siteHospital
}

// contextHospital 当前医院：-h 覆盖 > ma use 会话上下文 > 本站医院。
func (c *client) contextHospital(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	if s, err := loadSession(); err == nil && s.Hospital != "" {
		return s.Hospital, nil
	}
	if h := c.siteHospitalID(); h != "" {
		return h, nil
	}
	return "", errors.New(T("未设定当前医院：先 ma use <医院ID>（多院/实验室实例需要；单院部署自动取本站）", "no current hospital set: run ma use <hospital-id> first (needed on multi-hospital/lab instances; single-site deployments use the site hospital automatically)"))
}

// ---------- 口令 ----------

// readPassword 交互读取口令（TTY 时不回显）；非 TTY 时读一行（管道/脚本）。
func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// envPassword 从指定环境变量取口令（为空报错）。
func envPassword(envVar string) (string, error) {
	v := os.Getenv(envVar)
	if v == "" {
		return "", fmt.Errorf(T("环境变量 %s 未设置或为空", "environment variable %s is not set or is empty"), envVar)
	}
	return v, nil
}

// auditPassword 审计目标口令：-e 指定环境变量 > MEDAUDIT_PW > 交互输入。
func auditPassword(envVar, prompt string) (string, error) {
	if envVar != "" {
		return envPassword(envVar)
	}
	if v := os.Getenv("MEDAUDIT_PW"); v != "" {
		return v, nil
	}
	return readPassword(prompt)
}

// userPassword 平台账号口令：-e 指定环境变量 > 交互输入。
func userPassword(envVar, prompt string) (string, error) {
	if envVar != "" {
		return envPassword(envVar)
	}
	return readPassword(prompt)
}

func jsonUnmarshal(raw []byte, out any) error { return json.Unmarshal(raw, out) }

func printJSON(v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(raw))
	return nil
}
