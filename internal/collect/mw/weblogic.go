package mw

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"medaudit/internal/facts"
)

// ---------- WebLogic config.xml 结构（按本地名匹配，忽略命名空间） ----------

type wlDomain struct {
	XMLName               xml.Name      `xml:"domain"`
	Name                  string        `xml:"name"`
	DomainVersion         string        `xml:"domain-version"`
	ProductionModeEnabled string        `xml:"production-mode-enabled"`
	AdminServerName       string        `xml:"admin-server-name"`
	Servers               []wlServer    `xml:"server"`
	AppDeployments        []wlAppDeploy `xml:"app-deployment"`
}

type wlSSL struct {
	Enabled    string `xml:"enabled"`
	ListenPort string `xml:"listen-port"`
}

type wlServer struct {
	Name              string `xml:"name"`
	ListenPort        string `xml:"listen-port"`
	ListenPortEnabled string `xml:"listen-port-enabled"`
	ListenAddress     string `xml:"listen-address"`
	Cluster           string `xml:"cluster"`
	SSL               wlSSL  `xml:"ssl"`
}

type wlAppDeploy struct {
	Name       string `xml:"name"`
	Target     string `xml:"target"`
	ModuleType string `xml:"module-type"`
}

// CollectWebLogic 采集一个 WebLogic 域目录（--home 为域根目录，或直接指向 config/config.xml）。
// 说明：嵌入式 LDAP 内的用户/组存于二进制 .dat 文件，本采集器不解析（事实缺口会在文档中标明）。
func CollectWebLogic(opts Options) (*facts.FactBundle, error) {
	home := opts.Home
	domainRoot := home
	configPath := filepath.Join(home, "config", "config.xml")
	if info, err := os.Stat(home); err == nil && !info.IsDir() {
		configPath = home
		domainRoot = filepath.Dir(filepath.Dir(home))
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取域配置失败（--home 应为域根目录）: %w", err)
	}
	started := time.Now().UTC().Truncate(time.Second)
	bd := &builder{}

	var dom wlDomain
	if err := xml.Unmarshal(raw, &dom); err != nil {
		return nil, fmt.Errorf("解析 config.xml 失败: %w", err)
	}
	prodMode := strings.EqualFold(strings.TrimSpace(dom.ProductionModeEnabled), "true")

	// 1) 实例
	bd.fact(facts.FactServiceConfig, "weblogic", "mw.weblogic.instance", facts.StatusObserved,
		map[string]string{
			"domain": dom.Name, "domain_root": domainRoot, "config": configPath,
			"production_mode": boolStr(prodMode), "admin_server": dom.AdminServerName,
		})
	bd.receipt("mw.weblogic.instance", "ok", 1)

	// 2) 运行进程（weblogic.Server）
	procs := findProcesses(func(cmd string) bool {
		return strings.Contains(cmd, "weblogic.Server")
	})
	targetIdentity := "weblogic@" + domainRoot
	if len(procs) > 0 {
		p := procs[0]
		bd.fact(facts.FactProcess, "weblogic", "mw.weblogic.process", facts.StatusObserved,
			map[string]string{
				"pid": strconv.Itoa(p.PID), "run_user": p.User,
				"run_uid": strconv.Itoa(p.UID), "cmdline": truncate(p.Cmdline, 240),
			})
		bd.receipt("mw.weblogic.process", "ok", len(procs))
		if p.User != "" {
			targetIdentity = p.User + "@weblogic-process"
		}
	} else {
		bd.receipt("mw.weblogic.process", "partial", 0)
	}

	// 3) 服务器与监听
	for _, srv := range dom.Servers {
		sslEnabled := strings.EqualFold(strings.TrimSpace(srv.SSL.Enabled), "true")
		portEnabled := !strings.EqualFold(strings.TrimSpace(srv.ListenPortEnabled), "false")
		role := "managed"
		if srv.Name == dom.AdminServerName {
			role = "admin"
		}
		bd.fact(facts.FactServiceConfig, "server:"+srv.Name, "mw.weblogic.servers", facts.StatusObserved,
			map[string]string{
				"listen_port": srv.ListenPort, "listen_address": strings.TrimSpace(srv.ListenAddress),
				"listen_enabled": boolStr(portEnabled), "ssl_enabled": boolStr(sslEnabled),
				"ssl_port": srv.SSL.ListenPort, "role": role, "cluster": srv.Cluster,
			})
	}
	bd.receipt("mw.weblogic.servers", "ok", len(dom.Servers))

	// 4) 部署（含管理控制台）
	for _, app := range dom.AppDeployments {
		kind := "app"
		lname := strings.ToLower(app.Name)
		if lname == "console" || strings.HasPrefix(lname, "consoleapp") {
			kind = "console"
		}
		bd.fact(facts.FactServiceConfig, app.Name, "mw.weblogic.deployments", facts.StatusObserved,
			map[string]string{"app_kind": kind, "target": app.Target, "module_type": app.ModuleType})
	}
	bd.receipt("mw.weblogic.deployments", "ok", len(dom.AppDeployments))

	// 5) 域目录与配置权限
	pn := 0
	for _, p := range []string{domainRoot, filepath.Join(domainRoot, "config"), configPath} {
		attrs := permAttrs(p)
		if _, bad := attrs["error"]; bad {
			continue
		}
		attrs["path"] = p
		bd.fact(facts.FactFilePerm, p, "mw.weblogic.config_perms", facts.StatusObserved, attrs)
		pn++
	}
	if pn < 3 {
		bd.receipt("mw.weblogic.config_perms", "partial", pn)
	} else {
		bd.receipt("mw.weblogic.config_perms", "ok", pn)
	}

	return newBundle(opts, facts.TargetMWWebLogic, "mw-weblogic", targetIdentity, dom.DomainVersion, started, bd), nil
}
