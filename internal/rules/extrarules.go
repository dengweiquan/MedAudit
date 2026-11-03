package rules

import (
	"fmt"
	"strings"

	"medaudit/internal/facts"
)

// sshdEvidence 是两条 sshd 规则共用的证据门控：
//   - 读到 present=true 的 Observed 事实 → Ready；
//   - present=false（sshd_config 不存在）→ NotApplicable（未安装/未配置 sshd）；
//   - 读事实被拒绝 → Missing（权限不足）；
//   - 其余（无事实）按收据区分：无收据/失败 → Missing，成功但无事实 → Missing（包不一致，不判通过）。
func sshdEvidence(c *EvalContext) (EvidenceStatus, string) {
	// 收据先行：任何事实（哪怕是“安全”的 Observed 事实）不得绕过缺失、
	// 失败或截断的收据——否则一次不完整的采集会被读成“配置安全”而误判 PASS。
	if st, reason := receiptVerdict(c, "linux.sshd"); st != EvidenceReady {
		return st, reason
	}
	for _, f := range c.Bundle.Facts {
		if f.Source != "linux.sshd" {
			continue
		}
		switch f.Status {
		case facts.StatusObserved:
			if f.Attributes["present"] == "true" {
				return EvidenceReady, ""
			}
		case facts.StatusUnsupported:
			if f.Attributes["present"] == "false" {
				return EvidenceNotApplicable, "未安装/未配置 sshd（sshd_config 不存在），本规则不适用"
			}
		case facts.StatusPermissionDenied:
			return EvidenceMissing, "sshd_config 不可读（权限不足），无法判定"
		}
	}
	return EvidenceMissing, "linux.sshd 查询成功但无 sshd 配置事实，无法判定"
}

// linuxExtraRules Linux 补盲规则（M4-4b，sudoers 维度）。
// oracleSqlnetEvidence sqlnet.ora 规则的证据门控：宿主无 Oracle Home → 不适用；
// 其余按收据判定，要求至少一条有效 ENCRYPTION_SERVER 事实（缺省 accepted 已由采集器填好）。
func oracleSqlnetEvidence(c *EvalContext) (EvidenceStatus, string) {
	// 收据先行（与 sshdEvidence 同理）：失败的枚举不得被一张旧的“无 Home”
	// 盘点事实掩盖为不适用。
	if st, reason := receiptVerdict(c, "linux.oracle_sqlnet"); st != EvidenceReady {
		return st, reason
	}
	for _, f := range c.Bundle.Facts {
		if f.Source == "linux.oracle_sqlnet" && f.Attributes["oracle_homes"] == "0" {
			return EvidenceNotApplicable, "宿主无 Oracle Home，sqlnet.ora 检查不适用"
		}
	}
	for _, f := range c.Bundle.Facts {
		if f.Source != "linux.oracle_sqlnet" || f.Status != facts.StatusObserved {
			continue
		}
		switch strings.ToLower(f.Attributes["encryption_server"]) {
		case "required", "requested", "accepted", "rejected":
			return EvidenceReady, ""
		}
	}
	return EvidenceMissing, "linux.oracle_sqlnet 查询成功但无有效 ENCRYPTION_SERVER 事实，无法判定"
}

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
			ID: "os.linux.ssh_password_auth", Version: "3",
			Name:        "sshd 允许口令鉴别",
			Target:      facts.TargetOSLinux,
			Description: "sshd 允许口令鉴别时，远程管理依赖口令（可爆破、可窃听重放），应改用密钥鉴别。本规则只评价全局配置；Match 条件块（如针对特定用户/地址的例外）不在评价范围。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Evidence:    sshdEvidence,
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
			ID: "os.linux.ssh_root_login", Version: "4",
			Name:        "sshd 允许 root 口令登录",
			Target:      facts.TargetOSLinux,
			Description: "PermitRootLogin=yes 且口令鉴别未关闭时，root 可直接口令登录，远程爆破一旦成功即获最高权限。只看 PermitRootLogin 会误判：PasswordAuthentication=no 时 root 只能密钥登录，不判口令登录。本规则只评价全局配置；Match 条件块不在评价范围；键盘交互（PAM）等其他口令通道不在本规则评价范围。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Evidence:    sshdEvidence,
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
				// root 口令登录还需口令鉴别开启：PasswordAuthentication=no 时 root 只能密钥登录。
				pa := f.Attributes["password_authentication"]
				if pa != "" && strings.EqualFold(pa, "no") {
					continue
				}
				if c.Baseline.Allowed("sshd_config", "sshd", "permit_root_login", "") {
					continue
				}
				detail := "sshd 允许 root 口令登录（PermitRootLogin=yes，PasswordAuthentication=yes）"
				if pa == "" {
					detail = "sshd 允许 root 口令登录（PermitRootLogin=yes，PasswordAuthentication 缺省即 yes）"
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
			ID: "os.linux.oracle_native_encryption_not_required", Version: "2",
			Name:        "Oracle 未要求原生网络加密",
			Target:      facts.TargetOSLinux,
			Description: "宿主 Oracle Home 的 sqlnet.ora 中 SQLNET.ENCRYPTION_SERVER 不是 required 时，服务端不要求原生网络加密。注意：未要求原生加密不等于链路明文——TCPS 等传输层加密不在本规则评价范围，TCPS 部署记入基线豁免；文件缺失或参数缺失时取 Oracle 缺省 accepted；当前会话协商结果无可靠通道可取，不发会话证据。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Evidence:    oracleSqlnetEvidence,
			Risk:        RiskMedium,
			Remediation: "在 sqlnet.ora 中设 SQLNET.ENCRYPTION_SERVER=required（并配 ENCRYPTION_TYPES_SERVER）；或以 TCPS 覆盖全部连接并记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "linux.oracle_sqlnet" || f.Status != facts.StatusObserved {
					continue
				}
				v := strings.ToLower(f.Attributes["encryption_server"])
				if v == "required" {
					continue
				}
				if c.Baseline.Allowed(f.Subject, "parameter", "encryption_server", "") {
					continue
				}
				detail := fmt.Sprintf("Oracle Home %s 未要求原生网络加密（SQLNET.ENCRYPTION_SERVER=%s，文件 %s）",
					f.Subject, v, f.Attributes["sqlnet_file"])
				if f.Attributes["file_missing"] == "true" {
					detail += "；sqlnet.ora 缺失，取 Oracle 缺省 accepted"
				} else if f.Attributes["param_missing"] == "true" {
					detail += "；参数缺失，取 Oracle 缺省 accepted"
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   detail,
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
