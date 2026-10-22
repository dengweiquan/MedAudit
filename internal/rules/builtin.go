package rules

import (
	"fmt"
	"strings"

	"medaudit/internal/facts"
)

// DefaultRegistry 返回注册了 M2 内置规则的注册表。
func DefaultRegistry() *Registry {
	r := NewRegistry()
	for _, e := range builtinRules {
		_ = r.Register(e.spec, e.check) // 内置规则 ID 唯一，忽略重复错误
	}
	for _, e := range windowsBuiltinRules {
		_ = r.Register(e.spec, e.check)
	}
	for _, e := range postgresBuiltinRules {
		_ = r.Register(e.spec, e.check)
	}
	for _, e := range linuxExtraRules {
		_ = r.Register(e.spec, e.check)
	}
	for _, e := range hpuxRules {
		_ = r.Register(e.spec, e.check)
	}
	for _, e := range mysqlExtraRules {
		_ = r.Register(e.spec, e.check)
	}
	for _, e := range oracleExtraRules {
		_ = r.Register(e.spec, e.check)
	}
	for _, e := range oracleObjectRules {
		_ = r.Register(e.spec, e.check)
	}
	for _, e := range serverConfigRules {
		_ = r.Register(e.spec, e.check)
	}
	for _, e := range mwBuiltinRules {
		_ = r.Register(e.spec, e.check)
	}
	for _, e := range mw2BuiltinRules {
		_ = r.Register(e.spec, e.check)
	}
	return r
}

type builtinRule struct {
	spec  RuleSpec
	check CheckFunc
}

var builtinRules = []builtinRule{
	// ---------- OS Linux ----------
	{
		spec: RuleSpec{
			ID: "os.linux.root_mismatch", Version: "1",
			Name:        "服务配置用户与实际运行身份不一致",
			Target:      facts.TargetOSLinux,
			Description: "systemd 配置的 User 为非 root，但进程实际 EUID=0（启动者不等于运行者）。",
			Requires:    []facts.FactKind{facts.FactProcess},
			Risk:        RiskHigh,
			Remediation: "检查服务启动方式与提权路径，按基线修正配置或补例外说明。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactProcess] {
				cfgUser := f.Attributes["configured_user"]
				if cfgUser == "" || cfgUser == "root" {
					continue
				}
				if f.Attributes["euid"] == "0" {
					hits = append(hits, CheckHit{
						Subject:  f.Subject,
						Detail:   fmt.Sprintf("配置用户 %s，但实际 EUID=0（%s）", cfgUser, f.Attributes["comm"]),
						Evidence: []string{f.FactID},
					})
				}
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "os.linux.high_capabilities", Version: "1",
			Name:        "非 root 进程持有高能力",
			Target:      facts.TargetOSLinux,
			Description: "EUID 非 0 但有效能力集非空的进程；非 root 高能力不能简单判通过，需基线解释。",
			Requires:    []facts.FactKind{facts.FactProcess},
			Risk:        RiskHigh,
			Remediation: "确认业务必需的能力并记入基线，或降权运行。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactProcess] {
				if f.Attributes["role"] != "nonroot-with-caps" {
					continue
				}
				if c.Baseline.Allowed(f.Subject, "identity", "caps:"+f.Attributes["caps"], "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("非 root 进程持有能力：%s", f.Attributes["caps"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "os.linux.writable_service_file", Version: "1",
			Name:        "服务加载文件可被低权主体修改",
			Target:      facts.TargetOSLinux,
			Description: "服务可执行文件或单元文件本身可被 other/group 写；正常数据/日志目录可写不在此列（只看 d0）。",
			Requires:    []facts.FactKind{facts.FactFilePerm},
			Risk:        RiskHigh,
			Remediation: "收紧文件属主与模式，确保低权主体不能修改高权服务加载内容。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactFilePerm] {
				if !strings.HasSuffix(f.FactID, "-d0") {
					continue // 只看文件本身，不看父目录
				}
				if f.Attributes["writable_by_other"] == "true" || f.Attributes["writable_by_group"] == "true" {
					hits = append(hits, CheckHit{
						Subject: f.Subject,
						Detail: fmt.Sprintf("服务加载文件可写：other=%s group=%s（mode %s）",
							f.Attributes["writable_by_other"], f.Attributes["writable_by_group"], f.Attributes["mode"]),
						Evidence: []string{f.FactID},
					})
				}
			}
			return hits
		},
	},
	// ---------- MySQL ----------
	{
		spec: RuleSpec{
			ID: "db.mysql.global_admin", Version: "2",
			Name:        "MySQL 账号持有全局管理权限",
			Target:      facts.TargetDBMySQL,
			Description: "全局范围（*.*）的管理类权限：SUPER/SYSTEM_USER/FILE/RELOAD/SHUTDOWN/PROCESS；含经角色传递闭包间接持有（M8-2）。",
			Requires:    []facts.FactKind{facts.FactPrivilege},
			Risk:        RiskHigh,
			Remediation: "按最小权限回收全局管理权限，或记入基线说明业务必需。",
		},
		check: func(c *EvalContext) []CheckHit {
			admin := map[string]bool{
				"SUPER": true, "SYSTEM_USER": true, "FILE": true,
				"RELOAD": true, "SHUTDOWN": true, "PROCESS": true,
			}
			var hits []CheckHit
			directSet := map[string]bool{}
			for _, f := range c.ByKind[facts.FactPrivilege] {
				if f.Scope != "*.*" {
					continue
				}
				priv := strings.ToUpper(f.Attributes["privilege"])
				if !admin[priv] {
					continue
				}
				if c.Baseline.Allowed(f.Subject, "privilege", priv, "*.*") {
					continue
				}
				directSet[f.Subject+"|"+priv] = true
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("全局管理权限 %s（转授权=%s）", priv, f.Attributes["grant_option"]),
					Evidence: []string{f.FactID},
				})
			}
			// 经角色链间接持有（传递闭包）：直接循环看不见角色名下的授权
			ix := BuildEffectiveIndex(c.Bundle.Facts)
			for _, subj := range ix.Subjects() {
				if ix.IsRole(subj) {
					continue
				}
				for _, ep := range ix.PrivilegesOf(subj) {
					if ep.Direct || ep.Scope != "*.*" {
						continue
					}
					priv := strings.ToUpper(ep.Privilege)
					if !admin[priv] || directSet[subj+"|"+priv] {
						continue
					}
					if c.Baseline.Allowed(subj, "privilege", priv, "*.*") {
						continue
					}
					hits = append(hits, CheckHit{
						Subject:  subj,
						Detail:   fmt.Sprintf("经角色链 %s 间接持有全局管理权限 %s", strings.Join(ep.Via, " → "), priv),
						Evidence: ep.Evidence,
					})
				}
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "db.mysql.grant_option", Version: "1",
			Name:        "MySQL 全局权限带转授权",
			Target:      facts.TargetDBMySQL,
			Description: "全局权限附带 WITH GRANT OPTION，可扩散授权。",
			Requires:    []facts.FactKind{facts.FactPrivilege},
			Risk:        RiskMedium,
			Remediation: "回收转授权或记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactPrivilege] {
				if f.Scope != "*.*" {
					continue
				}
				g := f.Attributes["grant_option"]
				if g != "true" && g != "1" && !strings.EqualFold(g, "YES") {
					continue
				}
				priv := f.Attributes["privilege"]
				if c.Baseline.Allowed(f.Subject, "privilege", priv+":grant", "*.*") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("全局权限 %s 带转授权", priv),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	// ---------- SQL Server ----------
	{
		spec: RuleSpec{
			ID: "db.mssql.sysadmin", Version: "2",
			Name:        "SQL Server 登录属于 sysadmin",
			Target:      facts.TargetDBSQLSrv,
			Description: "固定服务器角色 sysadmin 成员拥有最高权限；含经服务器角色嵌套传递的间接成员（M8-2）。",
			Requires:    []facts.FactKind{facts.FactRoleEdge},
			Risk:        RiskHigh,
			Remediation: "按最小权限移出 sysadmin，或记入基线说明业务必需。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			ix := BuildEffectiveIndex(c.Bundle.Facts)
			for _, subj := range ix.Subjects() {
				if ix.IsRole(subj) {
					continue
				}
				for _, rp := range ix.RolesOf(subj) {
					if !strings.EqualFold(rp.Role, "sysadmin") {
						continue
					}
					if c.Baseline.Allowed(subj, "role", "sysadmin", "server") {
						continue
					}
					detail := "sysadmin 固定服务器角色成员"
					if len(rp.Path) > 2 {
						detail = fmt.Sprintf("经角色链 %s 间接成为 sysadmin 成员", strings.Join(rp.Path, " → "))
					}
					hits = append(hits, CheckHit{
						Subject:  subj,
						Detail:   detail,
						Evidence: rp.Evidence,
					})
				}
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "db.mssql.control_server", Version: "2",
			Name:        "SQL Server 显式 CONTROL SERVER 授权",
			Target:      facts.TargetDBSQLSrv,
			Description: "显式 GRANT CONTROL SERVER（非固定角色路径）；含经服务器角色传递闭包间接持有（M8-2）。",
			Requires:    []facts.FactKind{facts.FactPrivilege},
			Risk:        RiskHigh,
			Remediation: "回收显式高权或记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			directSet := map[string]bool{}
			for _, f := range c.ByKind[facts.FactPrivilege] {
				if !strings.EqualFold(f.Attributes["permission"], "CONTROL SERVER") {
					continue
				}
				if !strings.EqualFold(f.Attributes["state"], "GRANT") {
					continue // DENY 保留原样，不在此判 FAIL
				}
				if c.Baseline.Allowed(f.Subject, "privilege", "CONTROL SERVER", f.Scope) {
					continue
				}
				directSet[f.Subject] = true
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   "显式 GRANT CONTROL SERVER",
					Evidence: []string{f.FactID},
				})
			}
			// 经服务器角色间接持有 CONTROL SERVER（传递闭包）
			ix := BuildEffectiveIndex(c.Bundle.Facts)
			for _, subj := range ix.Subjects() {
				if ix.IsRole(subj) || directSet[subj] {
					continue
				}
				for _, rp := range ix.RolesOf(subj) {
					granted := false
					var roleFacts []string
					for _, pf := range c.ByKind[facts.FactPrivilege] {
						if pf.Subject != rp.Role {
							continue
						}
						if strings.EqualFold(pf.Attributes["permission"], "CONTROL SERVER") &&
							strings.EqualFold(pf.Attributes["state"], "GRANT") {
							granted = true
							roleFacts = append(roleFacts, pf.FactID)
						}
					}
					if !granted {
						continue
					}
					if c.Baseline.Allowed(subj, "privilege", "CONTROL SERVER", "server") {
						continue
					}
					hits = append(hits, CheckHit{
						Subject:  subj,
						Detail:   fmt.Sprintf("经角色链 %s 间接持有 CONTROL SERVER", strings.Join(rp.Path, " → ")),
						Evidence: append(append([]string{}, rp.Evidence...), roleFacts...),
					})
				}
			}
			return hits
		},
	},
	// ---------- Oracle ----------
	{
		spec: RuleSpec{
			ID: "db.oracle.dba_role", Version: "1",
			Name:        "Oracle 账号拥有 DBA 角色",
			Target:      facts.TargetDBOracle,
			Description: "直接或经角色嵌套获得 DBA 角色（PermissionPath 保留路径）。",
			Requires:    []facts.FactKind{facts.FactRoleEdge},
			Risk:        RiskHigh,
			Remediation: "按最小权限回收 DBA 角色，或记入基线说明业务必需。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactRoleEdge] {
				if len(f.PermissionPath) == 0 || !strings.EqualFold(f.PermissionPath[0], "DBA") {
					continue
				}
				if c.Baseline.Allowed(f.Subject, "role", "DBA", "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("DBA 角色路径：%s（激活=%s）", strings.Join(f.PermissionPath, "→"), f.Activation),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "db.oracle.sysdba_pwfile", Version: "1",
			Name:        "Oracle 密码文件 SYSDBA 授权",
			Target:      facts.TargetDBOracle,
			Description: "V$PWFILE_USERS 中的 SYSDBA/SYSOPER 授权；DBA 角色不等于 SYSDBA，单独建模。",
			Requires:    []facts.FactKind{facts.FactPrivilege},
			Risk:        RiskHigh,
			Remediation: "确认管理授权必要性，OSDBA 等 OS 认证来源另行核查。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactPrivilege] {
				if f.Source != "ora.pwfile_users" {
					continue
				}
				priv := strings.ToUpper(f.Attributes["privilege"])
				if priv != "SYSDBA" && priv != "SYSOPER" {
					continue
				}
				if c.Baseline.Allowed(f.Subject, "privilege", priv, "pwfile") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("密码文件授权 %s", priv),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "db.oracle.any_privilege", Version: "1",
			Name:        "Oracle ANY 类系统权限",
			Target:      facts.TargetDBOracle,
			Description: "如 SELECT ANY TABLE 等 ANY 类权限作用范围广。",
			Requires:    []facts.FactKind{facts.FactPrivilege},
			Risk:        RiskMedium,
			Remediation: "按最小权限细化到对象级授权，或记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactPrivilege] {
				priv := strings.ToUpper(f.Attributes["privilege"])
				if !strings.Contains(priv, " ANY ") && !strings.HasSuffix(priv, " ANY") {
					continue
				}
				if c.Baseline.Allowed(f.Subject, "privilege", priv, f.Scope) {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("ANY 类权限 %s（范围 %s）", priv, f.Scope),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
}
