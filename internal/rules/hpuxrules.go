package rules

import (
	"fmt"

	"medaudit/internal/facts"
)

// hpuxRules HP-UX 规则（M21）：与 os.linux 五项逐项映射 + HP-UX 特有面。
// 事实由 internal/collect/oshpux 的六个模板提供（Source 前缀 hpux.）。
var hpuxRules = []builtinRule{
	{
		spec: RuleSpec{
			ID: "os.hpux.multiple_uid0", Version: "1",
			Name:        "多个 UID 0 账号",
			Target:      facts.TargetOSHpux,
			Description: "除 root 外还有 UID=0 账号，等同多出一个无约束的超级用户，常见于后门或误配。",
			Requires:    []facts.FactKind{facts.FactIdentity},
			Risk:        RiskHigh,
			Remediation: "删除或改 UID 并核实账号来源；确为厂商必需的记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactIdentity] {
				if f.Source != "hpux.identity" || f.Subject == "root" {
					continue
				}
				if f.Attributes["uid"] != "0" {
					continue
				}
				if c.Baseline != nil && c.Baseline.Allowed(f.Subject, "identity", "uid0", "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("账号 %s 的 UID 为 0（等同 root），应删除或改 UID 并核实来源", f.Subject),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "os.hpux.weak_password_store", Version: "1",
			Name:        "口令哈希存放在世界可读的 passwd",
			Target:      facts.TargetOSHpux,
			Description: "未启用 Trusted Mode 且无 /etc/shadow（普通模式）：口令哈希留在 /etc/passwd，任何本地用户可读走离线破解。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskHigh,
			Remediation: "启用 Shadow Password（或迁移至 Trusted Mode/目录服务），口令哈希移出 passwd；同时设置口令 aging 与最小长度策略。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "hpux.auth_policy" || f.Subject != "hpux:password-store" {
					continue
				}
				if f.Attributes["mode"] == "standard" {
					hits = append(hits, CheckHit{
						Subject:  f.Subject,
						Detail:   "口令存储为普通模式：无 /etc/shadow、无 Trusted Mode（/tcb），哈希存放在世界可读的 /etc/passwd",
						Evidence: []string{f.FactID},
					})
				}
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "os.hpux.inetd_risky_service", Version: "1",
			Name:        "inetd 开启高危服务",
			Target:      facts.TargetOSHpux,
			Description: "inetd 托管的 tftp/bootps/r 系列/小服务（echo/daytime/chargen/discard）与明文 telnet/ftp 属历史高危面，应关闭或以 sshd/安全替代收敛。",
			Requires:    []facts.FactKind{facts.FactServiceConfig},
			Risk:        RiskHigh,
			Remediation: "在 /etc/inetd.conf 注释对应行并 inetd -c 重读；业务必需的（如个别设备 tftp）记入基线并做来源网段限制。",
		},
		check: func(c *EvalContext) []CheckHit {
			risky := map[string]bool{
				"tftp": true, "bootps": true, "echo": true, "daytime": true,
				"chargen": true, "discard": true, "rsh": true, "rlogin": true,
				"rexec": true, "telnet": true, "ftp": true,
			}
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactServiceConfig] {
				if f.Source != "hpux.inetd" || !risky[f.Subject] {
					continue
				}
				if c.Baseline != nil && c.Baseline.Allowed(f.Subject, "service", "inetd", "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("inetd 开启高危服务 %s（%s，运行用户 %s，程序 %s）", f.Subject, f.Attributes["protocol"], f.Attributes["user"], f.Attributes["server"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "os.hpux.writable_service_file", Version: "1",
			Name:        "启动/服务文件可被低权主体修改",
			Target:      facts.TargetOSHpux,
			Description: "inetd.conf、/sbin/init.d 启动脚本或 rc 配置可被 group/other 写——低权用户可改高权启动内容实现持久化提权。",
			Requires:    []facts.FactKind{facts.FactFilePerm},
			Risk:        RiskHigh,
			Remediation: "收紧属主与模式（root:sys、755/644），确保低权主体不能修改启动加载内容。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactFilePerm] {
				if f.Source != "hpux.startup_perm" {
					continue
				}
				if f.Attributes["writable_by_other"] == "true" || f.Attributes["writable_by_group"] == "true" {
					hits = append(hits, CheckHit{
						Subject: f.Subject,
						Detail: fmt.Sprintf("启动/服务文件可写：other=%s group=%s（mode %s，属主 %s）",
							f.Attributes["writable_by_other"], f.Attributes["writable_by_group"], f.Attributes["mode"], f.Attributes["owner"]),
						Evidence: []string{f.FactID},
					})
				}
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "os.hpux.setuid_unexpected", Version: "1",
			Name:        "基线外 setuid-root 二进制",
			Target:      facts.TargetOSHpux,
			Description: "setuid-root 二进制是经典提权面；系统自带集合之外的 setuid-root 文件应逐个核实（应用自研程序尤甚）。",
			Requires:    []facts.FactKind{facts.FactFilePerm},
			Risk:        RiskHigh,
			Remediation: "核实业务必需性，非必需的去掉 setuid 位（chmod u-s）；厂商必需的记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			vendor := map[string]bool{
				"/usr/bin/su": true, "/usr/bin/passwd": true, "/usr/bin/chsh": true,
				"/usr/bin/chfn": true, "/usr/bin/newgrp": true, "/usr/bin/at": true,
				"/usr/bin/crontab": true, "/usr/bin/sudo": true, "/usr/bin/login": true,
				"/usr/dt/bin/dtsession": true,
			}
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactFilePerm] {
				if f.Source != "hpux.setuid_files" || f.Attributes["setuid"] != "true" || f.Attributes["owner"] != "root" {
					continue
				}
				if vendor[f.Subject] {
					continue
				}
				if c.Baseline != nil && c.Baseline.Allowed(f.Subject, "setuid", "setuid-root", "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("基线外 setuid-root 二进制 %s（mode %s）", f.Subject, f.Attributes["mode"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "os.hpux.sudo_all", Version: "1",
			Name:        "sudo 全命令授权",
			Target:      facts.TargetOSHpux,
			Description: "非 root 主体可 sudo 执行任意命令（NOPASSWD 形态尤甚：凭据泄漏即等同无口令 root）。与 os.linux 两条 sudo 规则等效，本规则按授权形态在一个结论内区分。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskHigh,
			Remediation: "收窄到具体命令或取消 NOPASSWD；确属运维必需的逐个记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "hpux.sudo_rbac" || f.Subject == "root" {
					continue
				}
				if f.Attributes["commands_all"] != "true" {
					continue
				}
				if c.Baseline != nil && c.Baseline.Allowed(f.Subject, "sudo", "ALL", "") {
					continue
				}
				form := "需口令"
				if f.Attributes["nopasswd"] == "true" {
					form = "免密（NOPASSWD）"
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("sudoers 授权 %s 以 %s 执行 ALL（%s，%s）", f.Subject, f.Attributes["runas"], form, f.Attributes["file"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
}
