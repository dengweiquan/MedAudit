package rules

import (
	"fmt"
	"strconv"
	"strings"

	"medaudit/internal/facts"
)

// windowsBuiltinRules Windows 目标内置规则。
var windowsBuiltinRules = []struct {
	spec  RuleSpec
	check CheckFunc
}{
	{
		spec: RuleSpec{
			ID: "os.windows.svc_account_mismatch", Version: "1",
			Name:        "服务配置身份与实际进程身份不一致",
			Target:      facts.TargetOSWindows,
			Description: "服务配置的运行身份与进程令牌实际身份不一致；提权驻留的常见迹象。",
			Requires:    []facts.FactKind{facts.FactProcess},
			Risk:        RiskHigh,
			Remediation: "核查服务配置与进程启动链，确认身份变更是否经过变更流程。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactProcess] {
				if f.Source != "win.proc_token" {
					continue
				}
				configured := f.Attributes["configured_user"]
				actual := f.Attributes["actual_user"]
				if configured == "" || actual == "" {
					continue
				}
				if normalizeWinAccount(configured) != normalizeWinAccount(actual) {
					hits = append(hits, CheckHit{
						Subject: f.Subject,
						Detail: fmt.Sprintf("服务配置身份 %q，但进程实际以 %q 运行",
							configured, actual),
						Evidence: []string{f.FactID},
					})
				}
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "os.windows.writable_service_binary", Version: "1",
			Name:        "服务二进制可被低权主体修改",
			Target:      facts.TargetOSWindows,
			Description: "服务可执行文件的 DACL 存在授予 Everyone/Users/Authenticated Users 的显式写 ACE。",
			Requires:    []facts.FactKind{facts.FactFilePerm},
			Risk:        RiskHigh,
			Remediation: "收紧服务二进制的 DACL，移除低权主体的写权限。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactFilePerm] {
				if f.Source != "win.acl_check" {
					continue
				}
				if f.Attributes["writable_by_low_priv"] == "true" {
					hits = append(hits, CheckHit{
						Subject: f.Subject,
						Detail: fmt.Sprintf("低权主体可写：%s",
							f.Attributes["ace_hits"]),
						Evidence: []string{f.FactID},
					})
				}
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "os.windows.unexpected_admin", Version: "1",
			Name:        "Administrators 组成员异常",
			Target:      facts.TargetOSWindows,
			Description: "本地 Administrators 组成员不在基线允许清单中。",
			Requires:    []facts.FactKind{facts.FactRoleEdge},
			Risk:        RiskHigh,
			Remediation: "核查新增管理员身份的合法性，或将其纳入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactRoleEdge] {
				if f.Source != "win.group_enum" || len(f.PermissionPath) == 0 {
					continue
				}
				if !strings.EqualFold(f.PermissionPath[0], "Administrators") {
					continue
				}
				if c.Baseline != nil && c.Baseline.Allowed(f.Subject, "identity", f.Subject, "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject: f.Subject,
					Detail: fmt.Sprintf("本地管理员组成员：%s（未在基线中）",
						strings.Join(f.PermissionPath, " -> ")),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
}

// winReceiptVerdict 某 Windows 采集项的收据状态。
// Windows 采集收据的 ErrorStage 即错误原文（见 windows/collect.go addReceipt），
// 直接写入原因，不把所有失败都说成权限不足。
// 本函数假设每模板单收据（Windows 采集段每项只跑一次）。
func winReceiptVerdict(c *EvalContext, source string) (EvidenceStatus, string) {
	var saw bool
	for _, rc := range c.Bundle.Receipts {
		if rc.TemplateID != source {
			continue
		}
		saw = true
		switch rc.Status {
		case "ok":
		case "partial":
			return EvidencePartial, fmt.Sprintf("%s 证据被截断，不完整，无法确认通过", source)
		default:
			reason := rc.ErrorStage
			if reason == "" {
				reason = rc.Status
			}
			return EvidenceMissing, fmt.Sprintf("%s 采集失败：%s，无法判定", source, reason)
		}
	}
	if !saw {
		return EvidenceMissing, fmt.Sprintf("未采集到 %s 证据（旧包或未执行），无法判定", source)
	}
	return EvidenceReady, ""
}

// winEvidence 某 Windows 采集项的证据门控：收据成功 + 存在匹配的 Observed 事实。
func winEvidence(source string, match func(facts.Fact) bool) EvidenceCheck {
	return func(c *EvalContext) (EvidenceStatus, string) {
		if st, reason := winReceiptVerdict(c, source); st != EvidenceReady {
			return st, reason
		}
		for _, f := range c.Bundle.Facts {
			if f.Source == source && f.Status == facts.StatusObserved && match(f) {
				return EvidenceReady, ""
			}
		}
		return EvidenceMissing, fmt.Sprintf("%s 查询成功但无匹配事实，无法判定", source)
	}
}

// winAttrPresent 事实含某非空属性。
func winAttrPresent(attr string) func(facts.Fact) bool {
	return func(f facts.Fact) bool { return f.Attributes[attr] != "" }
}

// rdpEvidence RDP 规则的证据门控：RDP 关闭 → 不适用；开启但 NLA 未读到 → 缺失。
func rdpEvidence(c *EvalContext) (EvidenceStatus, string) {
	if st, reason := winReceiptVerdict(c, "win.rdp"); st != EvidenceReady {
		return st, reason
	}
	for _, f := range c.Bundle.Facts {
		if f.Source != "win.rdp" || f.Status != facts.StatusObserved {
			continue
		}
		switch f.Attributes["enabled"] {
		case "false":
			return EvidenceNotApplicable, "RDP 未开启，NLA 检查不适用"
		case "true":
			if f.Attributes["nla"] != "" {
				return EvidenceReady, ""
			}
			return EvidenceMissing, "RDP 已开启但未读到 NLA 配置，无法判定"
		}
	}
	return EvidenceMissing, "win.rdp 查询成功但无 RDP 配置事实，无法判定"
}

// windowsPasswordRules Windows 口令与 RDP 规则（NetUserModalsGet + secedit + 注册表）。
var windowsPasswordRules = []struct {
	spec  RuleSpec
	check CheckFunc
}{
	{
		spec: RuleSpec{
			ID: "os.windows.password_min_length", Version: "1",
			Name:        "Windows 口令最小长度不足",
			Target:      facts.TargetOSWindows,
			Description: "本地 SAM 或域默认策略的口令最小长度低于项目基线 8 位时，短口令易被爆破。阈值 8 位为项目基线选择（与 MySQL 口令长度口径一致），非未核实标准的规定值；覆盖范围见事实 scope（local-sam/domain-default），细粒度用户策略（FGPP/PSO）未覆盖，本机策略不代表全部域用户。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Evidence:    winEvidence("win.password_policy", winAttrPresent("min_password_length")),
			Risk:        RiskMedium,
			Remediation: "将口令最小长度提高到至少 8 位（组策略或本地安全策略）；确需短口令的记入基线并注明覆盖范围。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "win.password_policy" || f.Status != facts.StatusObserved {
					continue
				}
				n, err := strconv.Atoi(f.Attributes["min_password_length"])
				if err != nil || n >= 8 {
					continue
				}
				if c.Baseline.Allowed("password-policy", "policy", "min_length", f.Attributes["scope"]) {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  "password-policy",
					Detail:   fmt.Sprintf("口令最小长度为 %d 位，低于项目基线 8 位（覆盖范围：%s）", n, f.Attributes["scope"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "os.windows.password_max_age_never", Version: "1",
			Name:        "Windows 口令永不过期",
			Target:      facts.TargetOSWindows,
			Description: "MaximumPasswordAge 为 TIMEQ_FOREVER（永不过期）时，口令泄漏后长期有效。本规则只判永不过期，不对“过长但有限”的期限设阈值（无核实标准值可引）。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Evidence:    winEvidence("win.password_policy", winAttrPresent("max_password_age_sec")),
			Risk:        RiskMedium,
			Remediation: "为口令设置有限的最长使用期；确需永不过期的服务账号记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "win.password_policy" || f.Status != facts.StatusObserved {
					continue
				}
				v, err := strconv.ParseUint(f.Attributes["max_password_age_sec"], 10, 32)
				if err != nil || v != 0xFFFFFFFF {
					continue
				}
				if c.Baseline.Allowed("password-policy", "policy", "max_age_never", f.Attributes["scope"]) {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  "password-policy",
					Detail:   "口令永不过期（MaximumPasswordAge = TIMEQ_FOREVER）",
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "os.windows.password_lockout_disabled", Version: "1",
			Name:        "Windows 未启用登录失败锁定",
			Target:      facts.TargetOSWindows,
			Description: "LockoutThreshold=0（锁定阈值关闭）时，口令可被无限次尝试爆破。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Evidence:    winEvidence("win.password_policy", winAttrPresent("lockout_threshold")),
			Risk:        RiskMedium,
			Remediation: "设置登录失败锁定阈值（如 5 次）及锁定时长；确需关闭的记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "win.password_policy" || f.Status != facts.StatusObserved {
					continue
				}
				if f.Attributes["lockout_threshold"] != "0" {
					continue
				}
				if c.Baseline.Allowed("password-policy", "policy", "lockout", f.Attributes["scope"]) {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  "password-policy",
					Detail:   "未启用登录失败锁定（LockoutThreshold=0）",
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "os.windows.password_complexity_off", Version: "1",
			Name:        "Windows 未要求口令复杂度",
			Target:      facts.TargetOSWindows,
			Description: "secedit 导出的 PasswordComplexity=0 时，口令无复杂度要求。复杂度不能从 NetUserModalsGet 推断，本规则仅以 secedit 只读导出为准；导出渠道不可用时结论为 UNKNOWN，不解析本地化 net accounts 文案。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Evidence: winEvidence("win.secedit", func(f facts.Fact) bool {
				v := f.Attributes["password_complexity"]
				return v == "0" || v == "1"
			}),
			Risk:        RiskMedium,
			Remediation: "在安全策略中启用口令复杂度要求；确需关闭的记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "win.secedit" || f.Status != facts.StatusObserved {
					continue
				}
				if f.Attributes["password_complexity"] != "0" {
					continue
				}
				if c.Baseline.Allowed("password-policy", "policy", "complexity", f.Attributes["scope"]) {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  "password-policy",
					Detail:   "未要求口令复杂度（secedit PasswordComplexity=0）",
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "os.windows.rdp_nla_disabled", Version: "1",
			Name:        "RDP 未要求网络级身份验证",
			Target:      facts.TargetOSWindows,
			Description: "RDP 已开启但未要求网络级身份验证（NLA）时，远程桌面会话在身份验证前即建立，攻击面更大。仅开启 RDP 本身不判违规；RDP 关闭时本规则不适用。NLA 仅要求网络级身份验证，不等于来源 IP 限制。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Evidence:    rdpEvidence,
			Risk:        RiskMedium,
			Remediation: "在 RDP-Tcp 设置中启用“仅允许运行使用网络级别身份验证的远程桌面的计算机连接”（或组策略等效项）。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "win.rdp" || f.Status != facts.StatusObserved {
					continue
				}
				if f.Attributes["enabled"] != "true" || f.Attributes["nla"] == "true" {
					continue
				}
				if c.Baseline.Allowed("rdp", "rdp", "nla", "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  "rdp",
					Detail:   fmt.Sprintf("RDP 已开启但未要求 NLA（UserAuthentication≠1，来源：%s）", f.Attributes["nla_source"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
}

// normalizeWinAccount 归一化 Windows 账户名用于比较。
// 处理同一主体的不同写法：LocalService/LOCAL SERVICE、NetworkService/NETWORK SERVICE、LocalSystem/SYSTEM。
func normalizeWinAccount(a string) string {
	s := strings.ToUpper(strings.TrimSpace(a))
	// LocalSystem 与 NT AUTHORITY\SYSTEM 是同一主体（去空格前比较）
	if s == "LOCALSYSTEM" || s == "NT AUTHORITY\\SYSTEM" {
		return "NT AUTHORITY\\SYSTEM"
	}
	// 其他账户去空格比较（LocalService vs "LOCAL SERVICE"）
	return strings.ReplaceAll(s, " ", "")
}
