package rules

import (
	"fmt"
	"strings"

	"medaudit/internal/facts"
)

// M7-2 中间件规则（WebLogic / IIS）。

var mw2BuiltinRules = []builtinRule{
	// ---------- WebLogic ----------
	{
		spec: RuleSpec{
			ID: "mw.weblogic.run_as_root", Version: "1",
			Name:        "WebLogic 以 root 运行",
			Target:      facts.TargetMWWebLogic,
			Description: "WebLogic 进程实际 EUID=0。",
			Requires:    []facts.FactKind{facts.FactProcess},
			Risk:        RiskHigh,
			Remediation: "改用专用低权账号运行域进程，或在基线登记例外。",
		},
		check: func(c *EvalContext) []CheckHit { return runAsRootHit(c, "weblogic") },
	},
	{
		spec: RuleSpec{
			ID: "mw.weblogic.config_writable", Version: "1",
			Name:        "WebLogic 域配置可被非属主修改",
			Target:      facts.TargetMWWebLogic,
			Description: "域目录/config 目录/config.xml 对 group 或 other 可写。",
			Requires:    []facts.FactKind{facts.FactFilePerm},
			Risk:        RiskHigh,
			Remediation: "收紧域目录与配置权限。",
		},
		check: configWritableHits,
	},
	{
		spec: RuleSpec{
			ID: "mw.weblogic.dev_mode", Version: "1",
			Name:        "WebLogic 域处于开发模式",
			Target:      facts.TargetMWWebLogic,
			Description: "config.xml 的 production-mode-enabled 非 true（开发模式自动部署等行为开启）。",
			Requires:    []facts.FactKind{facts.FactServiceConfig},
			Risk:        RiskMedium,
			Remediation: "生产域切换为生产模式（production-mode-enabled=true）后重启域。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactServiceConfig] {
				if f.Source != "mw.weblogic.instance" {
					continue
				}
				if f.Attributes["production_mode"] != "true" {
					hits = append(hits, CheckHit{
						Subject:  "weblogic",
						Detail:   fmt.Sprintf("域 %s 未启用生产模式（production-mode-enabled=%s）", f.Attributes["domain"], f.Attributes["production_mode"]),
						Evidence: []string{f.FactID},
					})
				}
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "mw.weblogic.console_deployed", Version: "1",
			Name:        "WebLogic 管理控制台已部署",
			Target:      facts.TargetMWWebLogic,
			Description: "app-deployment 中存在管理控制台应用（console）。",
			Requires:    []facts.FactKind{facts.FactServiceConfig},
			Risk:        RiskMedium,
			Remediation: "通过 console-enabled=false 关闭控制台，或限制访问并在基线登记。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactServiceConfig] {
				if f.Attributes["app_kind"] != "console" {
					continue
				}
				if c.Baseline.Allowed(f.Subject, "deployment", "console", "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("管理控制台已部署（目标 %s）", f.Attributes["target"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "mw.weblogic.plain_listener", Version: "1",
			Name:        "WebLogic 明文监听对外暴露",
			Target:      facts.TargetMWWebLogic,
			Description: "服务器的普通（非 SSL）监听端口启用且绑定非回环地址（含未设地址=全网卡）。",
			Requires:    []facts.FactKind{facts.FactServiceConfig},
			Risk:        RiskMedium,
			Remediation: "明文监听仅绑内网/回环地址，或禁用普通端口只保留 SSL 监听。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactServiceConfig] {
				if !strings.HasPrefix(f.Subject, "server:") {
					continue
				}
				if f.Attributes["listen_enabled"] == "false" {
					continue
				}
				addr := f.Attributes["listen_address"]
				if addr == "127.0.0.1" || addr == "::1" || addr == "localhost" {
					continue
				}
				hits = append(hits, CheckHit{
					Subject: f.Subject,
					Detail: fmt.Sprintf("明文监听 %s:%s（角色 %s，SSL %s）",
						addrOrAll(addr), f.Attributes["listen_port"], f.Attributes["role"], f.Attributes["ssl_enabled"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},

	// ---------- IIS ----------
	{
		spec: RuleSpec{
			ID: "mw.iis.plain_binding", Version: "1",
			Name:        "IIS 明文绑定对外暴露",
			Target:      facts.TargetMWIIS,
			Description: "站点存在 http 绑定且 IP 非回环（* 或具体网卡地址）。",
			Requires:    []facts.FactKind{facts.FactServiceConfig},
			Risk:        RiskMedium,
			Remediation: "明文绑定仅绑回环或下线，对外走 https。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactServiceConfig] {
				if !strings.HasPrefix(f.Subject, "binding:") || f.Attributes["protocol"] != "http" {
					continue
				}
				ip := f.Attributes["ip"]
				if ip == "127.0.0.1" || ip == "::1" {
					continue
				}
				hits = append(hits, CheckHit{
					Subject: f.Subject,
					Detail: fmt.Sprintf("站点 %s 明文绑定 %s:%s",
						f.Attributes["site"], addrOrAll(ip), f.Attributes["port"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "mw.iis.anon_open", Version: "1",
			Name:        "IIS 站点匿名访问且无授权收窄",
			Target:      facts.TargetMWIIS,
			Description: "站点匿名认证开启（含架构默认）且授权规则未做任何收窄（无规则或仅 Allow *）。",
			Requires:    []facts.FactKind{facts.FactServiceConfig},
			Risk:        RiskMedium,
			Remediation: "业务允许时关闭匿名或用授权规则/其他认证收窄；纯公开站点在基线登记。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactServiceConfig] {
				if !strings.HasPrefix(f.Subject, "auth:") {
					continue
				}
				if f.Attributes["anonymous"] == "false" || f.Attributes["authz_open"] != "true" {
					continue
				}
				if c.Baseline.Allowed(f.Attributes["site"], "identity", "anonymous-open", "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject: f.Subject,
					Detail: fmt.Sprintf("站点 %s 匿名开启（来源 %s）且授权未收窄（规则数 %s）",
						f.Attributes["site"], f.Attributes["anonymous_source"], f.Attributes["authz_rules"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "mw.iis.apppool_system", Version: "1",
			Name:        "应用程序池以 LocalSystem 运行",
			Target:      facts.TargetMWIIS,
			Description: "应用程序池 processModel 身份为 LocalSystem（SYSTEM 全权）。",
			Requires:    []facts.FactKind{facts.FactIdentity},
			Risk:        RiskHigh,
			Remediation: "改用 ApplicationPoolIdentity 或专用低权账号，或在基线登记例外。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactIdentity] {
				if f.Attributes["identity_type"] != "LocalSystem" {
					continue
				}
				if c.Baseline.Allowed(f.Subject, "identity", "LocalSystem", "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("应用程序池 %s 以 LocalSystem 运行", f.Subject),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "mw.iis.default_site", Version: "1",
			Name:        "IIS 默认站点仍存在",
			Target:      facts.TargetMWIIS,
			Description: "Default Web Site 未删除（默认页与默认绑定扩大暴露面）。",
			Requires:    []facts.FactKind{facts.FactServiceConfig},
			Risk:        RiskLow,
			Remediation: "删除或停用默认站点。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactServiceConfig] {
				if f.Subject == "site:Default Web Site" {
					hits = append(hits, CheckHit{
						Subject:  f.Subject,
						Detail:   "默认站点 Default Web Site 仍存在",
						Evidence: []string{f.FactID},
					})
				}
			}
			return hits
		},
	},
}
