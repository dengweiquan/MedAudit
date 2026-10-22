package rules

import (
	"fmt"
	"strings"

	"medaudit/internal/facts"
)

// M7-1 中间件规则（Tomcat / Nginx）。判定纪律与既有规则一致：
// 只依据已采集事实下 FAIL；关键事实缺失时引擎按 Requires 给 UNKNOWN，不臆测。

func runAsRootHit(c *EvalContext, subject string) []CheckHit {
	var hits []CheckHit
	for _, f := range c.ByKind[facts.FactProcess] {
		if f.Attributes["run_uid"] != "0" {
			continue
		}
		if c.Baseline.Allowed(subject, "identity", "run-as-root", "") {
			continue
		}
		hits = append(hits, CheckHit{
			Subject: subject,
			Detail: fmt.Sprintf("中间件进程以 root 运行（pid %s，用户 %s）",
				f.Attributes["pid"], f.Attributes["run_user"]),
			Evidence: []string{f.FactID},
		})
	}
	return hits
}

func configWritableHits(c *EvalContext) []CheckHit {
	var hits []CheckHit
	for _, f := range c.ByKind[facts.FactFilePerm] {
		if f.Attributes["writable_by_other"] == "true" || f.Attributes["writable_by_group"] == "true" {
			hits = append(hits, CheckHit{
				Subject: f.Subject,
				Detail: fmt.Sprintf("配置文件/目录可被非属主写：other=%s group=%s（mode %s，owner %s）",
					f.Attributes["writable_by_other"], f.Attributes["writable_by_group"],
					f.Attributes["mode"], f.Attributes["owner"]),
				Evidence: []string{f.FactID},
			})
		}
	}
	return hits
}

// weakTLS 判断协议列表是否含 TLS1.0/1.1 或 SSL（按 token 精确匹配，避免 TLSv1.2 误伤）。
func weakTLS(protocols string) (string, bool) {
	for _, tok := range strings.FieldsFunc(protocols, func(r rune) bool {
		return r == ' ' || r == ',' || r == '+' || r == ':'
	}) {
		switch tok {
		case "TLSv1", "TLSv1.1", "SSLv2", "SSLv3", "SSL":
			return tok, true
		}
	}
	return "", false
}

var mwBuiltinRules = []builtinRule{
	// ---------- 通用维度（按目标各注册一份） ----------
	{
		spec: RuleSpec{
			ID: "mw.tomcat.run_as_root", Version: "1",
			Name:        "Tomcat 以 root 运行",
			Target:      facts.TargetMWTomcat,
			Description: "Tomcat 进程实际 EUID=0；Web 容器被攻破即等于主机 root。",
			Requires:    []facts.FactKind{facts.FactProcess},
			Risk:        RiskHigh,
			Remediation: "改用专用低权服务账号运行 Tomcat，并在基线登记例外（如确有必需）。",
		},
		check: func(c *EvalContext) []CheckHit { return runAsRootHit(c, "tomcat") },
	},
	{
		spec: RuleSpec{
			ID: "mw.nginx.run_as_root", Version: "1",
			Name:        "Nginx 主进程以 root 运行",
			Target:      facts.TargetMWNginx,
			Description: "Nginx master 进程 EUID=0（master 以 root 起始本身常见，但需结合 worker 用户判定；本规则仅提示复核）。",
			Requires:    []facts.FactKind{facts.FactProcess},
			Risk:        RiskMedium,
			Remediation: "确认 worker 进程为低权用户（user 指令）；master 必须 root 时在基线登记例外。",
		},
		check: func(c *EvalContext) []CheckHit { return runAsRootHit(c, "nginx") },
	},
	{
		spec: RuleSpec{
			ID: "mw.tomcat.config_writable", Version: "1",
			Name:        "Tomcat 配置可被非属主修改",
			Target:      facts.TargetMWTomcat,
			Description: "conf 目录/关键配置/webapps 对 group 或 other 可写，低权主体可篡改高权服务加载内容。",
			Requires:    []facts.FactKind{facts.FactFilePerm},
			Risk:        RiskHigh,
			Remediation: "收紧 conf 与 webapps 权限（属主 root/服务账号，组与他人只读或无权）。",
		},
		check: configWritableHits,
	},
	{
		spec: RuleSpec{
			ID: "mw.nginx.config_writable", Version: "1",
			Name:        "Nginx 配置可被非属主修改",
			Target:      facts.TargetMWNginx,
			Description: "主配置或其目录对 group 或 other 可写。",
			Requires:    []facts.FactKind{facts.FactFilePerm},
			Risk:        RiskHigh,
			Remediation: "收紧 Nginx 配置文件与目录权限。",
		},
		check: configWritableHits,
	},

	// ---------- Tomcat ----------
	{
		spec: RuleSpec{
			ID: "mw.tomcat.manager_deployed", Version: "1",
			Name:        "Tomcat 管理控制台已部署",
			Target:      facts.TargetMWTomcat,
			Description: "webapps 中存在 manager / host-manager 应用，管理面扩大了攻击面。",
			Requires:    []facts.FactKind{facts.FactServiceConfig},
			Risk:        RiskMedium,
			Remediation: "生产环境移除管理应用，或限制其访问来源并在基线登记。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactServiceConfig] {
				kind := f.Attributes["app_kind"]
				if kind != "manager" && kind != "host-manager" {
					continue
				}
				if c.Baseline.Allowed(f.Subject, "deployment", kind, "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject: f.Subject,
					Detail:  fmt.Sprintf("管理控制台应用已部署：%s（%s）", f.Subject, f.Attributes["path"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "mw.tomcat.console_admin", Version: "1",
			Name:        "控制台账号持有管理角色",
			Target:      facts.TargetMWTomcat,
			Description: "tomcat-users 中存在持有 manager/admin 类角色的账号且不在基线。",
			Requires:    []facts.FactKind{facts.FactIdentity},
			Risk:        RiskHigh,
			Remediation: "删除不必要的管理账号；确需保留的记入基线并配合访问来源限制。",
		},
		check: func(c *EvalContext) []CheckHit {
			adminRoles := map[string]bool{
				"manager-gui": true, "manager-script": true, "manager-jmx": true,
				"admin-gui": true, "admin-script": true,
			}
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactIdentity] {
				var granted []string
				for _, role := range strings.Split(f.Attributes["roles"], ",") {
					role = strings.TrimSpace(role)
					if adminRoles[role] && !c.Baseline.Allowed(f.Subject, "role", role, "") {
						granted = append(granted, role)
					}
				}
				if len(granted) > 0 {
					hits = append(hits, CheckHit{
						Subject:  f.Subject,
						Detail:   fmt.Sprintf("控制台账号 %s 持有管理角色：%s", f.Subject, strings.Join(granted, ", ")),
						Evidence: []string{f.FactID},
					})
				}
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "mw.tomcat.sample_apps", Version: "1",
			Name:        "Tomcat 示例应用已部署",
			Target:      facts.TargetMWTomcat,
			Description: "webapps 中存在 examples / docs 示例应用。",
			Requires:    []facts.FactKind{facts.FactServiceConfig},
			Risk:        RiskLow,
			Remediation: "生产环境删除 examples 与 docs 应用。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactServiceConfig] {
				kind := f.Attributes["app_kind"]
				if kind == "examples" || kind == "docs" {
					hits = append(hits, CheckHit{
						Subject:  f.Subject,
						Detail:   fmt.Sprintf("示例应用已部署：%s", f.Subject),
						Evidence: []string{f.FactID},
					})
				}
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "mw.tomcat.plain_listener", Version: "1",
			Name:        "Tomcat 明文监听对外暴露",
			Target:      facts.TargetMWTomcat,
			Description: "Connector 未启用 TLS 且监听非回环地址（含默认全网卡）。",
			Requires:    []facts.FactKind{facts.FactServiceConfig},
			Risk:        RiskMedium,
			Remediation: "明文 Connector 仅绑回环（address=127.0.0.1）或下线，对外走 TLS/反代。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactServiceConfig] {
				if !strings.HasPrefix(f.Subject, "connector:") {
					continue
				}
				if f.Attributes["tls"] == "true" {
					continue
				}
				addr := f.Attributes["address"]
				if addr == "127.0.0.1" || addr == "::1" || addr == "localhost" {
					continue
				}
				hits = append(hits, CheckHit{
					Subject: f.Subject,
					Detail: fmt.Sprintf("明文 Connector 监听 %s:%s（protocol %s）",
						addrOrAll(addr), f.Attributes["port"], f.Attributes["protocol"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "mw.tomcat.tls_weak", Version: "1",
			Name:        "Tomcat TLS 启用了弱协议",
			Target:      facts.TargetMWTomcat,
			Description: "Connector 的 SSLProtocol 含 TLSv1/TLSv1.1/SSL 或为 all（含弱协议）。",
			Requires:    []facts.FactKind{facts.FactServiceConfig},
			Risk:        RiskMedium,
			Remediation: "SSLProtocol 收紧为 TLSv1.2 起（建议 TLSv1.2,TLSv1.3）。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactServiceConfig] {
				if !strings.HasPrefix(f.Subject, "connector:") || f.Attributes["tls"] != "true" {
					continue
				}
				proto := f.Attributes["ssl_protocol"]
				if proto == "" {
					continue // 未显式配置：Tomcat 9 默认 TLS1.2+，无事实不臆测
				}
				if strings.EqualFold(proto, "all") {
					hits = append(hits, CheckHit{
						Subject: f.Subject,
						Detail:  fmt.Sprintf("Connector %s SSLProtocol=all（含弱协议）", f.Subject),
						Evidence: []string{f.FactID},
					})
					continue
				}
				if tok, weak := weakTLS(proto); weak {
					hits = append(hits, CheckHit{
						Subject:  f.Subject,
						Detail:   fmt.Sprintf("Connector %s 启用了弱 TLS 协议：%s（配置 %s）", f.Subject, tok, proto),
						Evidence: []string{f.FactID},
					})
				}
			}
			return hits
		},
	},

	// ---------- Nginx ----------
	{
		spec: RuleSpec{
			ID: "mw.nginx.plain_listener", Version: "1",
			Name:        "Nginx 明文监听对外暴露",
			Target:      facts.TargetMWNginx,
			Description: "server 块存在未启用 SSL 且监听非回环地址的 listen。",
			Requires:    []facts.FactKind{facts.FactServiceConfig},
			Risk:        RiskMedium,
			Remediation: "明文仅绑回环或跳转 HTTPS，对外服务走 TLS。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactServiceConfig] {
				if !strings.HasPrefix(f.Subject, "server:") {
					continue
				}
				if f.Attributes["ssl"] == "true" {
					continue
				}
				addr := f.Attributes["address"]
				if addr == "127.0.0.1" || addr == "::1" || addr == "localhost" {
					continue
				}
				hits = append(hits, CheckHit{
					Subject: f.Subject,
					Detail: fmt.Sprintf("明文监听 %s:%s（server_name %s）",
						addrOrAll(addr), f.Attributes["port"], f.Attributes["server_name"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "mw.nginx.tls_weak", Version: "1",
			Name:        "Nginx TLS 启用了弱协议",
			Target:      facts.TargetMWNginx,
			Description: "ssl_protocols 含 TLSv1 / TLSv1.1 / SSL。",
			Requires:    []facts.FactKind{facts.FactServiceConfig},
			Risk:        RiskMedium,
			Remediation: "ssl_protocols 收紧为 TLSv1.2 TLSv1.3。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactServiceConfig] {
				if !strings.HasPrefix(f.Subject, "tls:") {
					continue
				}
				if tok, weak := weakTLS(f.Attributes["protocols"]); weak {
					hits = append(hits, CheckHit{
						Subject:  f.Subject,
						Detail:   fmt.Sprintf("ssl_protocols 含弱协议 %s（配置：%s，作用域 %s）", tok, f.Attributes["protocols"], f.Attributes["context"]),
						Evidence: []string{f.FactID},
					})
				}
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "mw.nginx.autoindex", Version: "1",
			Name:        "Nginx 开启目录列表",
			Target:      facts.TargetMWNginx,
			Description: "存在 autoindex on 的作用域，目录内容可被浏览枚举。",
			Requires:    []facts.FactKind{facts.FactServiceConfig},
			Risk:        RiskMedium,
			Remediation: "关闭 autoindex（删除或改 off）。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactServiceConfig] {
				if strings.HasPrefix(f.Subject, "autoindex:") {
					hits = append(hits, CheckHit{
						Subject:  f.Subject,
						Detail:   fmt.Sprintf("autoindex 开启（作用域 %s）", f.Attributes["context"]),
						Evidence: []string{f.FactID},
					})
				}
			}
			return hits
		},
	},
}

func addrOrAll(addr string) string {
	if addr == "" {
		return "*"
	}
	return addr
}
