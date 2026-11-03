package rules

import (
	"fmt"
	"strings"

	"medaudit/internal/facts"
)

// linuxExtraRules Linux 补盲规则（M4-4b，sudoers 维度）。
var linuxExtraRules = []struct {
	spec  RuleSpec
	check CheckFunc
}{
	{
		spec: RuleSpec{
			ID: "os.linux.sudo_nopasswd_all", Version: "1",
			Name:        "sudo 免密全命令授权",
			Target:      facts.TargetOSLinux,
			Description: "非 root 主体持有 NOPASSWD: ALL —— 凭据泄漏即等同无口令 root。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskHigh,
			Remediation: "取消 NOPASSWD 或把命令收窄到具体二进制；确属自动化必需的记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "linux.sudo" || f.Subject == "root" {
					continue
				}
				if f.Attributes["nopasswd"] == "true" && f.Attributes["commands_all"] == "true" {
					hits = append(hits, CheckHit{
						Subject: f.Subject,
						Detail: fmt.Sprintf("sudoers 授权 %s 以 %s 免密执行 ALL（%s）",
							f.Subject, f.Attributes["runas"], f.Attributes["file"]),
						Evidence: []string{f.FactID},
					})
				}
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "os.linux.sudo_all", Version: "1",
			Name:        "sudo 全命令授权",
			Target:      facts.TargetOSLinux,
			Description: "非 root 主体可 sudo 执行任意命令（需口令）；成员范围应最小化并逐个核实。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskMedium,
			Remediation: "收窄到具体命令或核实成员必需性；发行版默认管理组（如 %sudo）可记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "linux.sudo" || f.Subject == "root" {
					continue
				}
				if f.Attributes["commands_all"] != "true" || f.Attributes["nopasswd"] == "true" {
					continue // NOPASSWD:ALL 由 os.linux.sudo_nopasswd_all 覆盖
				}
				if c.Baseline != nil && c.Baseline.Allowed(f.Subject, "sudo", "ALL", "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject: f.Subject,
					Detail: fmt.Sprintf("sudoers 授权 %s 以 %s 执行 ALL（%s，命令：%s）",
						f.Subject, f.Attributes["runas"], f.Attributes["file"], f.Attributes["commands"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "os.linux.ssh_password_auth", Version: "1",
			Name:        "sshd 允许口令鉴别",
			Target:      facts.TargetOSLinux,
			Description: "sshd 允许口令鉴别时，远程管理依赖口令（可爆破、可窃听重放），应改用密钥鉴别。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskMedium,
			Remediation: "将 PasswordAuthentication 设为 no，仅允许密钥登录；确需口令通道的记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "linux.sshd" || f.Status != facts.StatusObserved || f.Attributes["present"] != "true" {
					continue
				}
				v := f.Attributes["password_authentication"]
				explicit := v != ""
				if !explicit {
					v = "yes" // sshd 缺省即允许口令鉴别
				}
				if !strings.EqualFold(v, "yes") {
					continue
				}
				if c.Baseline.Allowed("sshd_config", "sshd", "password_authentication", "") {
					continue
				}
				detail := "sshd 允许口令鉴别（PasswordAuthentication=yes）"
				if !explicit {
					detail = "sshd 未禁用口令鉴别（缺省 PasswordAuthentication=yes）"
				}
				hits = append(hits, CheckHit{
					Subject:  "sshd_config",
					Detail:   detail,
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "os.linux.ssh_root_login", Version: "1",
			Name:        "sshd 允许 root 口令登录",
			Target:      facts.TargetOSLinux,
			Description: "PermitRootLogin=yes 时 root 可直接口令登录，远程爆破一旦成功即获最高权限。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskHigh,
			Remediation: "将 PermitRootLogin 设为 no 或 prohibit-password，root 仅经普通账号 sudo 提权。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "linux.sshd" || f.Status != facts.StatusObserved || f.Attributes["present"] != "true" {
					continue
				}
				if !strings.EqualFold(f.Attributes["permit_root_login"], "yes") {
					continue
				}
				if c.Baseline.Allowed("sshd_config", "sshd", "permit_root_login", "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  "sshd_config",
					Detail:   "sshd 允许 root 口令登录（PermitRootLogin=yes）",
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
}

// mysqlExtraRules MySQL 补盲规则（M4-4b，传输安全维度）。
var mysqlExtraRules = []struct {
	spec  RuleSpec
	check CheckFunc
}{
	{
		spec: RuleSpec{
			ID: "db.mysql.remote_no_tls", Version: "1",
			Name:        "远程 MySQL 账号未强制 TLS",
			Target:      facts.TargetDBMySQL,
			Description: "host='%' 的任意来源账号未要求 SSL（ssl_type 为空），口令与数据可走明文连接。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskMedium,
			Remediation: "对远程账号设置 REQUIRE SSL/X509，或收紧 host 范围；例外记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "mysql.account_tls" {
					continue
				}
				host := ""
				if i := strings.LastIndex(f.Subject, "@"); i >= 0 {
					host = f.Subject[i+1:]
				}
				if host != "%" || f.Attributes["ssl_type"] != "" {
					continue
				}
				if c.Baseline != nil && c.Baseline.Allowed(f.Subject, "tls", "none", "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("账号 %s 允许任意来源连接且未强制 TLS（ssl_type 为空）", f.Subject),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
}
