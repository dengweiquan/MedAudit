package mw

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"medaudit/internal/facts"
)

// ---------- server.xml / tomcat-users.xml 结构 ----------

type tcServer struct {
	XMLName  xml.Name     `xml:"Server"`
	Services []tcService  `xml:"Service"`
}
type tcService struct {
	Connectors []tcConnector `xml:"Connector"`
}
type tcConnector struct {
	Port        string `xml:"port,attr"`
	Protocol    string `xml:"protocol,attr"`
	SSLEnabled  string `xml:"SSLEnabled,attr"`
	Address     string `xml:"address,attr"`
	Scheme      string `xml:"scheme,attr"`
	SSLProtocol string `xml:"SSLProtocol,attr"`
}

type tcUsers struct {
	XMLName xml.Name  `xml:"tomcat-users"`
	Users   []tcUser  `xml:"user"`
}
type tcUser struct {
	Username string `xml:"username,attr"`
	Roles    string `xml:"roles,attr"`
	// 注意：password 属性刻意不解析——口令及其哈希一律不采集。
}

// tomcatVersion 从 lib/catalina.jar 的 MANIFEST 读 Implementation-Version；
// 失败再退 RELEASE-NOTES 首行；都没有返回空串（诚实缺失）。
func tomcatVersion(home string) string {
	if rc, err := zip.OpenReader(filepath.Join(home, "lib", "catalina.jar")); err == nil {
		defer rc.Close()
		for _, f := range rc.File {
			if f.Name == "META-INF/MANIFEST.MF" {
				r, err := f.Open()
				if err != nil {
					break
				}
				buf := make([]byte, 8192)
				n, _ := r.Read(buf)
				r.Close()
				for _, line := range strings.Split(string(buf[:n]), "\n") {
					if strings.HasPrefix(line, "Implementation-Version:") {
						return strings.TrimSpace(strings.TrimPrefix(line, "Implementation-Version:"))
					}
				}
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(home, "RELEASE-NOTES")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "Apache Tomcat Version") {
				parts := strings.Fields(line)
				return parts[len(parts)-1]
			}
		}
	}
	return ""
}

// CollectTomcat 采集一个 CATALINA_HOME。
func CollectTomcat(opts Options) (*facts.FactBundle, error) {
	home := opts.Home
	serverXMLPath := filepath.Join(home, "conf", "server.xml")
	rawServer, err := os.ReadFile(serverXMLPath)
	if err != nil {
		return nil, fmt.Errorf("读取 %s 失败（--home 应为 CATALINA_HOME）: %w", serverXMLPath, err)
	}
	started := time.Now().UTC().Truncate(time.Second)
	bd := &builder{}
	version := tomcatVersion(home)

	// 1) 实例
	bd.fact(facts.FactServiceConfig, "tomcat", "mw.tomcat.instance", facts.StatusObserved,
		map[string]string{"version": version, "home": home})
	bd.receipt("mw.tomcat.instance", "ok", 1)

	// 2) 运行进程（按 catalina.home 匹配；找不到则不出发 process 事实 → 相关规则 UNKNOWN）
	procs := findProcesses(func(cmd string) bool {
		return strings.Contains(cmd, "org.apache.catalina.startup.Bootstrap") &&
			(strings.Contains(cmd, "catalina.home="+home) || strings.Contains(cmd, "catalina.base="+home))
	})
	targetIdentity := "tomcat@" + home
	if len(procs) > 0 {
		p := procs[0]
		bd.fact(facts.FactProcess, "tomcat", "mw.tomcat.process", facts.StatusObserved,
			map[string]string{
				"pid": strconv.Itoa(p.PID), "run_user": p.User,
				"run_uid": strconv.Itoa(p.UID), "cmdline": truncate(p.Cmdline, 240),
			})
		bd.receipt("mw.tomcat.process", "ok", len(procs))
		if p.User != "" {
			targetIdentity = p.User + "@tomcat-process"
		}
	} else {
		bd.receipt("mw.tomcat.process", "partial", 0)
	}

	// 3) server.xml 连接器
	var srv tcServer
	if err := xml.Unmarshal(rawServer, &srv); err != nil {
		bd.receipt("mw.tomcat.server_xml", "failed", 0)
	} else {
		n := 0
		for _, svc := range srv.Services {
			for _, c := range svc.Connectors {
				tls := strings.EqualFold(c.SSLEnabled, "true") || strings.EqualFold(c.Scheme, "https")
				bd.fact(facts.FactServiceConfig, "connector:"+c.Port, "mw.tomcat.server_xml", facts.StatusObserved,
					map[string]string{
						"port": c.Port, "protocol": c.Protocol, "tls": boolStr(tls),
						"address": c.Address, "ssl_protocol": c.SSLProtocol,
					})
				n++
			}
		}
		bd.receipt("mw.tomcat.server_xml", "ok", n)
	}

	// 4) tomcat-users（只记账号与角色）
	usersPath := filepath.Join(home, "conf", "tomcat-users.xml")
	if raw, err := os.ReadFile(usersPath); err != nil {
		bd.receipt("mw.tomcat.users", "partial", 0)
	} else {
		var us tcUsers
		if err := xml.Unmarshal(raw, &us); err != nil {
			bd.receipt("mw.tomcat.users", "failed", 0)
		} else {
			for _, u := range us.Users {
				bd.fact(facts.FactIdentity, u.Username, "mw.tomcat.users", facts.StatusObserved,
					map[string]string{"roles": u.Roles, "password_set": "true"})
			}
			bd.receipt("mw.tomcat.users", "ok", len(us.Users))
		}
	}

	// 5) 部署应用
	webapps := filepath.Join(home, "webapps")
	entries, err := os.ReadDir(webapps)
	if err != nil {
		bd.receipt("mw.tomcat.deployments", "partial", 0)
	} else {
		n := 0
		for _, e := range entries {
			name := e.Name()
			app := name
			if strings.HasSuffix(name, ".war") {
				app = strings.TrimSuffix(name, ".war")
			}
			kind := "app"
			switch app {
			case "manager":
				kind = "manager"
			case "host-manager":
				kind = "host-manager"
			case "examples":
				kind = "examples"
			case "docs":
				kind = "docs"
			case "ROOT":
				kind = "root"
			}
			bd.fact(facts.FactServiceConfig, app, "mw.tomcat.deployments", facts.StatusObserved,
				map[string]string{"app_kind": kind, "path": filepath.Join(webapps, name)})
			n++
		}
		bd.receipt("mw.tomcat.deployments", "ok", n)
	}

	// 6) 关键文件/目录权限
	permPaths := []string{
		filepath.Join(home, "conf"), serverXMLPath, usersPath, webapps,
	}
	pn := 0
	for _, p := range permPaths {
		attrs := permAttrs(p)
		if _, bad := attrs["error"]; bad {
			continue
		}
		attrs["path"] = p
		bd.fact(facts.FactFilePerm, p, "mw.tomcat.config_perms", facts.StatusObserved, attrs)
		pn++
	}
	if pn < len(permPaths) {
		bd.receipt("mw.tomcat.config_perms", "partial", pn)
	} else {
		bd.receipt("mw.tomcat.config_perms", "ok", pn)
	}

	return newBundle(opts, facts.TargetMWTomcat, "mw-tomcat", targetIdentity, version, started, bd), nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
