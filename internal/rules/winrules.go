package rules

import (
	"fmt"
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
