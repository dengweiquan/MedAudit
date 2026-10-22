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

// ---------- applicationHost.config 结构 ----------

type iisConfig struct {
	XMLName   xml.Name      `xml:"configuration"`
	AppHost   iisAppHost    `xml:"system.applicationHost"`
	Locations []iisLocation `xml:"location"`
}

type iisAppHost struct {
	Pools iisPools `xml:"applicationPools"`
	Sites iisSites `xml:"sites"`
}

type iisPools struct {
	Adds []iisPool `xml:"add"`
}

type iisPool struct {
	Name        string       `xml:"name,attr"`
	ProcessModel iisProcModel `xml:"processModel"`
}

type iisProcModel struct {
	IdentityType string `xml:"identityType,attr"`
	UserName     string `xml:"userName,attr"`
}

type iisSites struct {
	Sites []iisSite `xml:"site"`
}

type iisSite struct {
	Name     string         `xml:"name,attr"`
	ID       string         `xml:"id,attr"`
	Apps     []iisApp       `xml:"application"`
	Bindings iisBindings    `xml:"bindings"`
}

type iisApp struct {
	Path            string `xml:"path,attr"`
	ApplicationPool string `xml:"applicationPool,attr"`
}

type iisBindings struct {
	Bindings []iisBinding `xml:"binding"`
}

type iisBinding struct {
	Protocol           string `xml:"protocol,attr"`
	BindingInformation string `xml:"bindingInformation,attr"`
}

type iisLocation struct {
	Path        string        `xml:"path,attr"`
	WebServer   iisWebServer  `xml:"system.webServer"`
}

type iisWebServer struct {
	Security iisSecurity `xml:"security"`
}

type iisSecurity struct {
	Authentication iisAuth  `xml:"authentication"`
	Authorization  iisAuthz `xml:"authorization"`
}

type iisAuth struct {
	Anonymous iisAuthToggle `xml:"anonymousAuthentication"`
	Windows   iisAuthToggle `xml:"windowsAuthentication"`
}

type iisAuthToggle struct {
	Enabled *string `xml:"enabled,attr"`
}

type iisAuthz struct {
	Rules []iisAuthzRule `xml:"add"`
}

type iisAuthzRule struct {
	AccessType string `xml:"accessType,attr"`
	Users      string `xml:"users,attr"`
	Roles      string `xml:"roles,attr"`
}

// CollectIIS 采集 IIS 的 applicationHost.config。
// --home 可为配置文件路径、其所在目录，或为空（默认 %SystemRoot%\System32\inetsrv\config\applicationHost.config，仅 Windows）。
// 说明：IIS 配置文件 ACL 属 Windows ACL 体系，不在本采集器范围（由 OS 采集的 ACL 事实覆盖主机文件）。
func CollectIIS(opts Options) (*facts.FactBundle, error) {
	home := opts.Home
	configPath := home
	if home == "" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		configPath = filepath.Join(root, "System32", "inetsrv", "config", "applicationHost.config")
	} else if info, err := os.Stat(home); err == nil && info.IsDir() {
		configPath = filepath.Join(home, "applicationHost.config")
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取 applicationHost.config 失败: %w", err)
	}
	started := time.Now().UTC().Truncate(time.Second)
	bd := &builder{}

	var cfg iisConfig
	if err := xml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("解析 applicationHost.config 失败: %w", err)
	}

	// 位置（location）按站点名索引
	locBySite := map[string]*iisLocation{}
	for i := range cfg.Locations {
		loc := &cfg.Locations[i]
		if loc.Path != "" && !strings.Contains(loc.Path, "/") {
			locBySite[loc.Path] = loc
		}
	}

	// 1) 实例
	bd.fact(facts.FactServiceConfig, "iis", "mw.iis.instance", facts.StatusObserved,
		map[string]string{
			"config": configPath,
			"sites":  strconv.Itoa(len(cfg.AppHost.Sites.Sites)),
			"pools":  strconv.Itoa(len(cfg.AppHost.Pools.Adds)),
		})
	bd.receipt("mw.iis.instance", "ok", 1)

	// 2) 应用程序池身份
	for _, pool := range cfg.AppHost.Pools.Adds {
		identity := pool.ProcessModel.IdentityType
		if identity == "" {
			identity = "ApplicationPoolIdentity" // IIS 默认
		}
		bd.fact(facts.FactIdentity, "apppool:"+pool.Name, "mw.iis.pools", facts.StatusObserved,
			map[string]string{"identity_type": identity, "user": pool.ProcessModel.UserName})
	}
	bd.receipt("mw.iis.pools", "ok", len(cfg.AppHost.Pools.Adds))

	// 3) 站点、绑定与认证
	siteCount := 0
	for _, site := range cfg.AppHost.Sites.Sites {
		pool := ""
		for _, app := range site.Apps {
			if app.ApplicationPool != "" {
				pool = app.ApplicationPool
				break
			}
		}
		bd.fact(facts.FactServiceConfig, "site:"+site.Name, "mw.iis.sites", facts.StatusObserved,
			map[string]string{"site_id": site.ID, "app_pool": pool, "bindings": strconv.Itoa(len(site.Bindings.Bindings))})
		siteCount++

		for _, b := range site.Bindings.Bindings {
			ip, port, hostHeader := parseBindingInfo(b.BindingInformation)
			bd.fact(facts.FactServiceConfig,
				fmt.Sprintf("binding:%s:%s:%s", site.Name, b.Protocol, port),
				"mw.iis.sites", facts.StatusObserved,
				map[string]string{
					"site": site.Name, "protocol": b.Protocol,
					"ip": ip, "port": port, "host_header": hostHeader,
				})
		}

		// 认证：无 location 覆盖时用 IIS 架构默认值（匿名开启、无授权收窄）
		anon, anonSource, windowsAuth := "true", "default", "false"
		authzRules, authzOpen := 0, true
		if loc, ok := locBySite[site.Name]; ok {
			sec := loc.WebServer.Security
			if sec.Authentication.Anonymous.Enabled != nil {
				anon, anonSource = strings.ToLower(*sec.Authentication.Anonymous.Enabled), "config"
			}
			if sec.Authentication.Windows.Enabled != nil {
				windowsAuth = strings.ToLower(*sec.Authentication.Windows.Enabled)
			}
			authzRules = len(sec.Authorization.Rules)
			authzOpen = authzRules == 0
			for _, r := range sec.Authorization.Rules {
				if strings.EqualFold(r.AccessType, "Allow") && (r.Users == "*" || r.Users == "") && r.Roles == "" {
					authzOpen = true
				}
				if strings.EqualFold(r.AccessType, "Deny") && r.Users == "*" {
					authzOpen = false
				}
			}
		}
		bd.fact(facts.FactServiceConfig, "auth:"+site.Name, "mw.iis.auth", facts.StatusObserved,
			map[string]string{
				"site": site.Name, "anonymous": anon, "anonymous_source": anonSource,
				"windows_auth": windowsAuth, "authz_rules": strconv.Itoa(authzRules),
				"authz_open": boolStr(authzOpen),
			})
	}
	bd.receipt("mw.iis.sites", "ok", siteCount)
	bd.receipt("mw.iis.auth", "ok", siteCount)

	targetIdentity := "iis@" + configPath
	return newBundle(opts, facts.TargetMWIIS, "mw-iis", targetIdentity, "", started, bd), nil
}

// parseBindingInfo 解析 bindingInformation（IP:端口:主机头；IPv6 以方括号）。
func parseBindingInfo(info string) (ip, port, host string) {
	parts := strings.Split(info, ":")
	if len(parts) < 2 {
		return info, "", ""
	}
	ip = parts[0]
	port = parts[1]
	if len(parts) >= 3 {
		host = parts[2]
	}
	return ip, port, host
}
