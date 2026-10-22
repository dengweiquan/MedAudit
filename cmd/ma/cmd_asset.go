package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ---------- 资产 ----------

func cmdAssetList(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "k", value: true}, {name: "j"}})
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	rows, err := fetchAssets(c)
	if err != nil {
		return err
	}
	var out []assetRow
	for _, a := range rows {
		if p.str("k") == "" || a.Kind == p.str("k") {
			out = append(out, a)
		}
	}
	if p.has("j") {
		return printJSON(out)
	}
	fmt.Printf("%-18s %-12s %-12s %-22s %s\n", "资产", "医院", "类型", "名称", "端点")
	for _, a := range out {
		ep := ""
		if a.Endpoint != nil {
			ep = *a.Endpoint
		}
		fmt.Printf("%-18s %-12s %-12s %-22s %s\n", a.ID, a.HospitalID, a.Kind, a.Name, ep)
	}
	fmt.Printf("共 %d 个资产\n", len(out))
	return nil
}

func cmdAssetShow(args []string) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	if err := p.requirePos(1, "maassetshow <id>"); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	a, err := findAsset(c, p.pos[0])
	if err != nil {
		return err
	}
	ep, labels := "", ""
	if a.Endpoint != nil {
		ep = *a.Endpoint
	}
	if a.Labels != nil {
		labels = *a.Labels
	}
	fmt.Printf("资产 %s\n  医院 %s · 类型 %s · 名称 %s\n  端点 %s\n", a.ID, a.HospitalID, a.Kind, a.Name, ep)
	if labels != "" {
		var pretty any
		if err := json.Unmarshal([]byte(labels), &pretty); err == nil {
			raw, _ := json.MarshalIndent(pretty, "  ", "  ")
			fmt.Printf("  参数 %s\n", string(raw))
		} else {
			fmt.Printf("  参数 %s\n", labels)
		}
	}
	return nil
}

var dbKinds = map[string]struct {
	engine        string
	defaultPort   int
	nameIsService bool
}{
	"db-oracle":    {"oracle", 1521, true},
	"db-mysql":     {"mysql", 3306, false},
	"db-sqlserver": {"sqlserver", 1433, false},
	"db-postgres":  {"postgres", 5432, false},
}

var winrmKinds = map[string]bool{"os-windows": true, "mw-iis": true}
var sshKinds = map[string]bool{"os-linux": true, "os-hpux": true, "mw-tomcat": true, "mw-nginx": true, "mw-weblogic": true}

func splitHostPort(hp string, defPort int) (string, int) {
	host, port := hp, defPort
	if i := strings.LastIndex(hp, ":"); i > 0 {
		if n, err := strconv.Atoi(hp[i+1:]); err == nil {
			host, port = hp[:i], n
		}
	}
	return host, port
}

func splitUserHost(ep string) (user, hostport string) {
	if i := strings.Index(ep, "@"); i > 0 {
		return ep[:i], ep[i+1:]
	}
	return "", ep
}

func sanitizeIDPart(s string) string {
	r := strings.NewReplacer(".", "-", ":", "-", "/", "-", "_", "-")
	return strings.ToLower(r.Replace(s))
}

// buildAssetLabels 按类型与端点（LVM 式位置参数）生成 labels：
//   - db 类：host[:port]/库名或服务名（Oracle）
//   - winrm 类：[user@]host[:port]
//   - ssh 类：[user@]host[:port]；中间件本地目录：端点直接给目录路径
//
// 返回 (endpoint 字段, labels JSON, 主机名用于默认 ID)。
func buildAssetLabels(kind, ep, user, serverURL, mwHome, services string) (string, string, string, error) {
	if ep == "-" {
		return "", "", "", nil
	}
	if spec, ok := dbKinds[kind]; ok {
		i := strings.LastIndex(ep, "/")
		if i <= 0 || i == len(ep)-1 {
			return "", "", "", fmt.Errorf("数据库端点格式：host[:port]/%s，如 10.0.0.11:1521/HISDB", map[bool]string{true: "服务名", false: "库名"}[spec.nameIsService])
		}
		host, port := splitHostPort(ep[:i], spec.defaultPort)
		conn := map[string]any{"engine": spec.engine, "host": host, "port": port}
		if spec.nameIsService {
			conn["service"] = ep[i+1:]
		} else {
			conn["dbname"] = ep[i+1:]
		}
		if user != "" {
			conn["user"] = user
		}
		raw, _ := json.Marshal(conn)
		return fmt.Sprintf("%s:%d", host, port), string(raw), host, nil
	}
	if strings.HasPrefix(ep, "/") && strings.HasPrefix(kind, "mw-") {
		// 中间件本地目录型（如 WebLogic 域目录、本机 Tomcat）：无远程参数
		labels := map[string]any{"mw_home": ep, "mw_type": strings.TrimPrefix(kind, "mw-")}
		raw, _ := json.Marshal(labels)
		base := ep[strings.LastIndex(strings.TrimRight(ep, "/"), "/")+1:]
		return ep, string(raw), base, nil
	}
	if winrmKinds[kind] {
		u, hp := splitUserHost(ep)
		host, port := splitHostPort(hp, 5985)
		if u == "" {
			u = user
		}
		labels := map[string]any{"transport": "winrm", "host": host, "port": port, "user": u, "server_url": serverURL}
		if kind == "mw-iis" {
			labels["mw_type"] = "iis"
		}
		raw, _ := json.Marshal(labels)
		return fmt.Sprintf("%s:%d", host, port), string(raw), host, nil
	}
	if sshKinds[kind] {
		u, hp := splitUserHost(ep)
		host, port := splitHostPort(hp, 22)
		if u == "" {
			u = user
		}
		labels := map[string]any{"transport": "ssh", "host": host, "port": port, "user": u}
		if mwHome != "" {
			labels["mw_home"] = mwHome
		}
		if services != "" {
			labels["services"] = services
		}
		raw, _ := json.Marshal(labels)
		return fmt.Sprintf("%s:%d", host, port), string(raw), host, nil
	}
	return ep, "", ep, nil
}

var assetFlagSpecs = []flagSpec{
	{name: "i", value: true}, {name: "n", value: true}, {name: "u", value: true},
	{name: "h", value: true}, {name: "f", value: true}, {name: "U", value: true},
	{name: "d", value: true}, {name: "s", value: true},
}

func cmdAssetAdd(args []string) error {
	p, err := parseArgs(args, assetFlagSpecs)
	if err != nil {
		return err
	}
	if err := p.requirePos(2, "maassetadd <类型> <端点> [-i id] [-n 名称] [-u 账号] [-h 医院] [-f labels文件] [-U 回连地址] [-d 中间件目录] [-s 服务清单]"); err != nil {
		return err
	}
	kind, ep := p.pos[0], p.pos[1]
	c, err := newClient()
	if err != nil {
		return err
	}
	hospital, err := c.contextHospital(p.str("h"))
	if err != nil {
		return err
	}
	serverURL := p.str("U")
	if serverURL == "" {
		serverURL = c.base
	}
	endpoint, labels, hostPart, err := buildAssetLabels(kind, ep, p.str("u"), serverURL, p.str("d"), p.str("s"))
	if err != nil {
		return err
	}
	if p.str("f") != "" {
		raw, err := os.ReadFile(p.str("f"))
		if err != nil {
			return err
		}
		var probe map[string]any
		if err := json.Unmarshal(raw, &probe); err != nil {
			return fmt.Errorf("labels 文件不是合法 JSON: %w", err)
		}
		labels = string(raw)
		if endpoint == "" {
			endpoint = ep
		}
	}
	id := p.str("i")
	if id == "" {
		if hostPart == "" {
			return fmt.Errorf("端点为 - 时须用 -i 指定资产 ID")
		}
		id = kind + "-" + sanitizeIDPart(hostPart)
	}
	name := p.str("n")
	if name == "" {
		name = id
	}
	body := map[string]any{"id": id, "hospital_id": hospital, "kind": kind, "name": name, "endpoint": endpoint, "labels": labels}
	var out map[string]any
	if err := c.postJSON("/api/v1/assets", body, &out); err != nil {
		return err
	}
	fmt.Printf("资产 %s 已登记（%s · %s · %s）\n", id, hospital, kind, endpoint)
	return nil
}

func cmdAssetMod(args []string) error {
	p, err := parseArgs(args, assetFlagSpecs)
	if err != nil {
		return err
	}
	if err := p.requirePos(1, "maassetmod <id> [端点] [-n 名称] [-u 账号] [-f labels文件] [-U 回连地址] [-d 中间件目录] [-s 服务清单]"); err != nil {
		return err
	}
	id := p.pos[0]
	c, err := newClient()
	if err != nil {
		return err
	}
	cur, err := findAsset(c, id)
	if err != nil {
		return err
	}
	name := cur.Name
	if p.str("n") != "" {
		name = p.str("n")
	}
	endpoint := ""
	if cur.Endpoint != nil {
		endpoint = *cur.Endpoint
	}
	labels := ""
	if cur.Labels != nil {
		labels = *cur.Labels
	}
	if p.str("f") != "" {
		raw, err := os.ReadFile(p.str("f"))
		if err != nil {
			return err
		}
		var probe map[string]any
		if err := json.Unmarshal(raw, &probe); err != nil {
			return fmt.Errorf("labels 文件不是合法 JSON: %w", err)
		}
		labels = string(raw)
	} else if len(p.pos) > 1 {
		serverURL := p.str("U")
		if serverURL == "" {
			serverURL = c.base
		}
		ep, lb, _, err := buildAssetLabels(cur.Kind, p.pos[1], p.str("u"), serverURL, p.str("d"), p.str("s"))
		if err != nil {
			return err
		}
		endpoint, labels = ep, lb
	} else if p.str("u") != "" || p.str("d") != "" || p.str("s") != "" || p.str("U") != "" {
		// 在现有 labels 上做字段级覆盖
		m := map[string]any{}
		if labels != "" {
			_ = json.Unmarshal([]byte(labels), &m)
		}
		if p.str("u") != "" {
			m["user"] = p.str("u")
		}
		if p.str("d") != "" {
			m["mw_home"] = p.str("d")
		}
		if p.str("s") != "" {
			m["services"] = p.str("s")
		}
		if p.str("U") != "" {
			m["server_url"] = p.str("U")
		}
		raw, _ := json.Marshal(m)
		labels = string(raw)
	}
	body := map[string]any{"kind": cur.Kind, "name": name, "endpoint": endpoint, "labels": labels}
	if _, _, err := c.do("PUT", "/api/v1/assets/"+escapePath(id), body); err != nil {
		return err
	}
	fmt.Printf("资产 %s 已更新\n", id)
	return nil
}

func cmdAssetDelete(args []string) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	if err := p.requirePos(1, "maassetrm <id>"); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	if _, _, err := c.do("DELETE", "/api/v1/assets/"+escapePath(p.pos[0]), nil); err != nil {
		return err
	}
	fmt.Printf("资产 %s 已删除（登记移除；历史事实包/报告保留）\n", p.pos[0])
	return nil
}
