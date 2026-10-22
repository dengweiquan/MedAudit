package rules

import (
	"fmt"
	"strings"

	"medaudit/internal/facts"
)

// oracleExtraRules Oracle 补盲规则（M4-4c，CDB 跨容器维度）。
var oracleExtraRules = []struct {
	spec  RuleSpec
	check CheckFunc
}{
	{
		spec: RuleSpec{
			ID: "db.oracle.cdb_dba_in_pdb", Version: "1",
			Name:        "PDB 容器内授予 DBA 角色",
			Target:      facts.TargetDBOracle,
			Description: "从 CDB$ROOT 视角可见某个 PDB（CON_ID≠1）内存在 DBA 授予；PDB 本地视角与根容器常规检查都容易漏掉。",
			Requires:    []facts.FactKind{facts.FactRoleEdge},
			Risk:        RiskHigh,
			Remediation: "核实该 PDB 内 DBA 的业务必需性；回收或记入基线（与 db.oracle.dba_role 共用 role/DBA 豁免）。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactRoleEdge] {
				if f.Source != "ora.cdb_role_privs" || len(f.PermissionPath) == 0 {
					continue
				}
				if !strings.EqualFold(f.PermissionPath[0], "DBA") {
					continue
				}
				if f.Attributes["con_id"] == "" || f.Attributes["con_id"] == "1" {
					continue // 根容器授予由 db.oracle.dba_role 覆盖，避免重复
				}
				if c.Baseline != nil && c.Baseline.Allowed(f.Subject, "role", "DBA", "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject: f.Subject,
					Detail: fmt.Sprintf("主体 %s 在容器 CON_ID=%s 被授予 DBA（common=%s，激活=%s）",
						f.Subject, f.Attributes["con_id"], f.Attributes["common"], f.Activation),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
}


// oracleMaintainedNames 汇总「厂商维护」主体集合：优先用事实自带的
// oracle_maintained 标记（ora.cdb_users），再并入内置 19c 厂商账号清单兜底
// （纯 PDB 采集无 CDB 事实时使用）。组件版本化模式（APEX_190200 等）按前缀识别。
func oracleMaintainedNames(c *EvalContext) map[string]bool {
	m := map[string]bool{}
	for _, f := range c.ByKind[facts.FactAccountConfig] {
		if f.Source == "ora.cdb_users" && strings.EqualFold(f.Attributes["oracle_maintained"], "Y") {
			m[strings.ToUpper(f.Subject)] = true
		}
	}
	for _, n := range []string{
		"SYS", "SYSTEM", "SYSBACKUP", "SYSDG", "SYSKM", "SYSRAC", "XS$NULL", "SYS$UMF",
		"ANONYMOUS", "APPQOSSYS", "AUDSYS", "CTXSYS", "DBSNMP", "DIP", "DVF", "DVSYS",
		"EXFSYS", "GSMADMIN_INTERNAL", "GSMCATUSER", "GSMUSER", "LBACSYS", "MDSYS",
		"MGMT_VIEW", "OLAPSYS", "ORACLE_OCM", "ORDPLUGINS", "ORDSYS", "OUTLN",
		"REMOTE_SCHEDULER_AGENT", "SI_INFORMTN_SCHEMA", "WMSYS", "XDB",
		"APEX_PUBLIC_USER", "FLOWS_FILES",
	} {
		m[n] = true
	}
	return m
}

func oracleMaintained(m map[string]bool, name string) bool {
	u := strings.ToUpper(name)
	return m[u] || strings.HasPrefix(u, "APEX_")
}

// oracleUserNames 事实中的真实用户集合（ora.users + ora.cdb_users 的主体）。
// Oracle 用户与角色共用命名空间：不在此集合的被授者即角色。
func oracleUserNames(c *EvalContext) map[string]bool {
	m := map[string]bool{}
	for _, f := range c.ByKind[facts.FactAccountConfig] {
		if f.Source == "ora.users" || f.Source == "ora.cdb_users" {
			m[strings.ToUpper(f.Subject)] = true
		}
	}
	return m
}

func scopeOwner(scope string) string {
	if i := strings.Index(scope, "."); i > 0 {
		return scope[:i]
	}
	return scope
}

// oracleObjectRules Oracle 对象权限与默认账号规则（M13）。
// 全部基于既有采集事实（ora.tab_privs / ora.users），不新增采集模板。
// 噪声控制（经存量实测校准）：Oracle 组件模式/账号之间存在大量厂商内部互授
// （MDSYS 对 PUBLIC 发布 2605 条、组件账号持有 SYS 对象授权等），一律以
// oracle_maintained 标记 + 内置厂商清单豁免；只判业务侧的真实暴露面。
var oracleObjectRules = []struct {
	spec  RuleSpec
	check CheckFunc
}{
	{
		spec: RuleSpec{
			ID: "db.oracle.public_object_grant", Version: "1",
			Name:        "Oracle 对象授权给 PUBLIC",
			Target:      facts.TargetDBOracle,
			Description: "对象权限授予 PUBLIC 等于对所有用户与角色开放。判定口径：对象所有者为业务模式（非厂商维护）时任意 PUBLIC 授权判 FAIL；所有者为厂商维护模式时，仅当对象属敏感字典对象（USER$、DBA_USERS 等口令/授权字典）才判 FAIL——厂商组件对 PUBLIC 的常规发布（EXECUTE/目录查询）是产品基线，不判以免噪声淹没真实问题。",
			Requires:    []facts.FactKind{facts.FactPrivilege},
			Risk:        RiskHigh,
			Remediation: "将 PUBLIC 授权改为按角色/用户的定向授权；确属全院共用的只读业务对象记入基线（按对象豁免）。",
		},
		check: func(c *EvalContext) []CheckHit {
			maint := oracleMaintainedNames(c)
			sensitive := map[string]bool{
				"USER$": true, "USER_HISTORY$": true, "DEFAULT_PWD$": true,
				"LINK$": true, "DBA_USERS": true, "DBA_TAB_PRIVS": true,
				"DBA_SYS_PRIVS": true, "DBA_ROLE_PRIVS": true,
			}
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactPrivilege] {
				if f.Source != "ora.tab_privs" || !strings.EqualFold(f.Subject, "PUBLIC") {
					continue
				}
				owner := scopeOwner(f.Scope)
				obj := f.Scope
				if i := strings.Index(obj, "."); i > 0 {
					obj = obj[i+1:]
				}
				if oracleMaintained(maint, owner) && !sensitive[strings.ToUpper(obj)] {
					continue // 厂商基线发布，不判
				}
				priv := strings.ToUpper(f.Attributes["privilege"])
				if c.Baseline != nil && c.Baseline.Allowed("PUBLIC", "privilege", priv, f.Scope) {
					continue
				}
				hits = append(hits, CheckHit{
					Subject: "PUBLIC",
					Detail: fmt.Sprintf("对象 %s 的 %s 权限授予 PUBLIC（所有用户与角色可达）",
						f.Scope, priv),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "db.oracle.sys_schema_grant", Version: "1",
			Name:        "Oracle 系统模式对象被业务用户持有",
			Target:      facts.TargetDBOracle,
			Description: "SYS/SYSTEM 模式对象（数据字典与系统包）被业务用户直接持有，等于把字典读写面交给业务侧。判定口径：被授者须是事实中的真实用户（用户与角色共用命名空间，不在用户清单中的被授者是角色——厂商目录角色与管理角色持有 SYS 授权属产品设计，不判）；厂商维护账号（组件账号）豁免；DBA 角色持有归 db.oracle.dba_role 口径，不在此重复。",
			Requires:    []facts.FactKind{facts.FactPrivilege},
			Risk:        RiskHigh,
			Remediation: "回收业务用户对系统模式对象的直接授权，改走 SELECT_CATALOG_ROLE 等厂商角色；个别必需授权记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			maint := oracleMaintainedNames(c)
			users := oracleUserNames(c)
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactPrivilege] {
				if f.Source != "ora.tab_privs" {
					continue
				}
				owner := scopeOwner(f.Scope)
				if owner != "SYS" && owner != "SYSTEM" {
					continue
				}
				grantee := strings.ToUpper(f.Subject)
				if grantee == "PUBLIC" || !users[grantee] || oracleMaintained(maint, grantee) {
					continue
				}
				priv := strings.ToUpper(f.Attributes["privilege"])
				if c.Baseline != nil && c.Baseline.Allowed(f.Subject, "privilege", priv, f.Scope) {
					continue
				}
				hits = append(hits, CheckHit{
					Subject: f.Subject,
					Detail: fmt.Sprintf("业务用户 %s 持有系统模式对象 %s 的 %s 授权",
						f.Subject, f.Scope, priv),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "db.oracle.grant_option_spread", Version: "1",
			Name:        "Oracle 对象授权带 GRANT OPTION 可转授",
			Target:      facts.TargetDBOracle,
			Description: "对象授权带 GRANT OPTION 时，被授者可把同一权限继续转授任意第三方，权限边界失控且回收时产生级联。厂商维护主体之间、厂商维护对象上的内部转授属产品机制，不判；只判业务侧的转授能力。",
			Requires:    []facts.FactKind{facts.FactPrivilege},
			Risk:        RiskMedium,
			Remediation: "回收 GRANT OPTION 后以普通授权重新下发；确需分级下发的场景记入基线（privilege 以 :grant 后缀登记）。",
		},
		check: func(c *EvalContext) []CheckHit {
			maint := oracleMaintainedNames(c)
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactPrivilege] {
				if f.Source != "ora.tab_privs" || f.Grantable == nil || !*f.Grantable {
					continue
				}
				if oracleMaintained(maint, f.Subject) || oracleMaintained(maint, scopeOwner(f.Scope)) {
					continue // 厂商内部转授机制，不判
				}
				priv := strings.ToUpper(f.Attributes["privilege"])
				if c.Baseline != nil && c.Baseline.Allowed(f.Subject, "privilege", priv+":grant", f.Scope) {
					continue
				}
				hits = append(hits, CheckHit{
					Subject: f.Subject,
					Detail: fmt.Sprintf("主体 %s 对对象 %s 的 %s 授权带 GRANT OPTION（可再转授）",
						f.Subject, f.Scope, priv),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "db.oracle.default_account_open", Version: "1",
			Name:        "Oracle 厂商默认账号未锁定",
			Target:      facts.TargetDBOracle,
			Description: "厂商默认/示例账号（DBSNMP、OUTLN、SCOTT、HR 等内置清单）处于 OPEN 状态：这类账号的初始口令是公开知识，未锁定等于留了一扇已知钥匙的门。仅判 OPEN（已过期 EXPIRED 须改密后才能用，风险口径不同，不在此列）；EM 组件在用的 DBSNMP/SYSMAN 如属实请记入基线豁免。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskMedium,
			Remediation: "锁定不使用的默认账号（ALTER USER ... ACCOUNT LOCK）；确在用者改强口令并记入基线说明用途。",
		},
		check: func(c *EvalContext) []CheckHit {
			defaults := map[string]bool{
				"ANONYMOUS": true, "APPQOSSYS": true, "AUDSYS": true, "BI": true,
				"CTXSYS": true, "DBSNMP": true, "DIP": true, "EXFSYS": true,
				"HR": true, "IX": true, "LBACSYS": true, "MDSYS": true,
				"MGMT_VIEW": true, "OE": true, "OLAPSYS": true, "ORACLE_OCM": true,
				"ORDPLUGINS": true, "ORDSYS": true, "OUTLN": true, "PM": true,
				"SCOTT": true, "SH": true, "SI_INFORMTN_SCHEMA": true,
				"SYSMAN": true, "WMSYS": true, "XDB": true,
			}
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "ora.users" {
					continue
				}
				if !defaults[strings.ToUpper(f.Subject)] {
					continue
				}
				if !strings.EqualFold(f.Attributes["account_status"], "OPEN") {
					continue
				}
				if c.Baseline != nil && c.Baseline.Allowed(f.Subject, "identity", "default-account-open", "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject: f.Subject,
					Detail: fmt.Sprintf("厂商默认/示例账号 %s 处于 OPEN 状态（profile=%s）",
						f.Subject, f.Attributes["profile"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
}
