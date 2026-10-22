package remediation

import (
	"fmt"
	"strings"

	"medaudit/internal/facts"
)

func init() {
	generators["db.mssql.sysadmin"] = msSysadmin
	generators["db.mssql.control_server"] = msControlServer
	generators["db.mssql.xp_cmdshell"] = msSpConfigure("xp_cmdshell", "xp_cmdshell",
		"xp_cmdshell 允许以服务账号执行操作系统命令，是提权与横向移动的高危开关；关闭不影响常规 T-SQL 业务。")
	generators["db.mssql.clr_enabled"] = msSpConfigure("clr enabled", "clr_enabled",
		"CLR 启用允许在数据库内运行 .NET 程序集；确有 CLR 程序集在用时应改走基线备案并逐个核 UNSAFE/EXTERNAL_ACCESS 程序集。")
	generators["db.mssql.cross_db_chaining"] = msSpConfigure("cross db ownership chaining", "cross_db_chaining",
		"跨库所有权链接会让低权库的权限跨库放大；关闭后个别依赖链接链的跨库过程可能报错，先在测试窗口验证。")
	generators["db.mssql.adhoc_distributed"] = msSpConfigure("Ad Hoc Distributed Queries", "adhoc_distributed",
		"即席分布式查询允许 OPENROWSET/OPENDATASOURCE 访问外部数据源，易被用于数据外带；常规业务应改用链接服务器并单独授权。")
}

// roleEdges 挑证据中的角色边（Subject=成员，PermissionPath[0]=角色）。
func roleEdges(ev []facts.Fact) []facts.Fact {
	var out []facts.Fact
	for _, f := range ev {
		if f.Kind == facts.FactRoleEdge && len(f.PermissionPath) > 0 {
			out = append(out, f)
		}
	}
	return out
}

func msSysadmin(subject string, ev []facts.Fact) *Script {
	edges := roleEdges(ev)
	// 直接成员：一条命令精确回收。
	for _, e := range edges {
		if e.Subject == subject && e.PermissionPath[0] == "sysadmin" {
			return &Script{
				RuleID: "db.mssql.sysadmin", Subject: subject,
				Precheck: fmt.Sprintf("SELECT p.name FROM sys.server_role_members rm JOIN sys.server_principals r ON r.principal_id = rm.role_principal_id JOIN sys.server_principals p ON p.principal_id = rm.member_principal_id WHERE r.name = 'sysadmin' AND p.name = %s;", sq(subject)),
				Fix:      fmt.Sprintf("ALTER SERVER ROLE [sysadmin] DROP MEMBER %s;", br(subject)),
				Verify:   "EXEC sp_helpsrvrolemember 'sysadmin';  -- 结果中不应再有该登录",
				Rollback: fmt.Sprintf("ALTER SERVER ROLE [sysadmin] ADD MEMBER %s;", br(subject)),
				Note:     "回收立即生效于新会话；执行前确认该登录没有依赖 sysadmin 的作业/维护计划。若为应用服务账号，应改为按最小权限新建专用角色。",
			}
		}
	}
	// 间接（经 Windows 组/登录链）：给指导型脚本，不擅自切断组关系。
	if len(edges) > 0 {
		var chain []string
		for _, e := range edges {
			chain = append(chain, fmt.Sprintf("-- 链路段：%s ∈ %s", e.Subject, e.PermissionPath[0]))
		}
		return &Script{
			RuleID: "db.mssql.sysadmin", Subject: subject,
			Precheck: "EXEC sp_helpsrvrolemember 'sysadmin';",
			Fix: "-- 指导型整改：该登录经中间主体间接获得 sysadmin，没有可无损直改的单条命令。\n" +
				strings.Join(chain, "\n") +
				"\n-- 两种切断方式（按影响从小到大，人工选一）：\n" +
				"-- (a) 若中间主体是 Windows 组：在域/本地用户管理中把该登录移出该组（影响面最小，仅该登录）；\n" +
				"-- (b) 若中间主体是组登录且整组都不应有 sysadmin：ALTER SERVER ROLE [sysadmin] DROP MEMBER [中间主体];（整组成员都会失去）",
			Verify:   "EXEC sp_helpsrvrolemember 'sysadmin';  -- 并以该登录新开会话执行 SELECT IS_SRVROLEMEMBER('sysadmin'); 应为 0",
			Rollback: "-- 回滚与所选切断方式对应：(a) 把登录加回原组；(b) ALTER SERVER ROLE [sysadmin] ADD MEMBER [中间主体];",
			Note:     "间接授权的切断点选择属于变更评审事项，本脚本只定位链路不断言改法；执行后用 maaudit 复测确认。",
		}
	}
	return nil
}

func msControlServer(subject string, ev []facts.Fact) *Script {
	// 直接授权的服务器权限事实
	for _, f := range ev {
		if f.Source == "mssql.server_permissions" && f.Subject == subject &&
			strings.EqualFold(f.Attributes["permission"], "CONTROL SERVER") {
			return &Script{
				RuleID: "db.mssql.control_server", Subject: subject,
				Precheck: fmt.Sprintf("SELECT * FROM sys.server_permissions WHERE grantee_principal_id = USER_ID(%s);", sq(subject)),
				Fix:      fmt.Sprintf("REVOKE CONTROL SERVER FROM %s;", br(subject)),
				Verify:   fmt.Sprintf("SELECT IS_SRVROLEMEMBER('sysadmin', %s); SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'CONTROL SERVER');  -- 以该登录会话验证应为 0", sq(subject)),
				Rollback: fmt.Sprintf("GRANT CONTROL SERVER TO %s;", br(subject)),
				Note:     "CONTROL SERVER 等价于 sysadmin 级别控制权；回收前确认没有依赖它的监控/备份代理账号。",
			}
		}
	}
	// 经服务器角色中转：回收主体在该角色中的成员资格（精确且影响面最小）。
	privRoles := map[string]bool{}
	for _, f := range ev {
		if f.Source == "mssql.server_permissions" &&
			strings.EqualFold(f.Attributes["permission"], "CONTROL SERVER") {
			privRoles[f.Subject] = true
		}
	}
	for _, e := range roleEdges(ev) {
		if e.Subject == subject && privRoles[e.PermissionPath[0]] {
			role := e.PermissionPath[0]
			return &Script{
				RuleID: "db.mssql.control_server", Subject: subject, Scope: role,
				Precheck: fmt.Sprintf("EXEC sp_helpsrvrolemember %s;", sq(role)),
				Fix:      fmt.Sprintf("ALTER SERVER ROLE %s DROP MEMBER %s;", br(role), br(subject)),
				Verify:   fmt.Sprintf("EXEC sp_helpsrvrolemember %s;  -- 不应再有该登录", sq(role)),
				Rollback: fmt.Sprintf("ALTER SERVER ROLE %s ADD MEMBER %s;", br(role), br(subject)),
				Note:     fmt.Sprintf("该主体的 CONTROL SERVER 来自服务器角色 %s 的成员资格；回收成员资格不影响角色本身对其它成员的授权。", role),
			}
		}
	}
	return nil
}

// msSpConfigure sp_configure 型开关：回滚用证据捕获的 value_in_use 原值。
func msSpConfigure(option, ruleKey, note string) generator {
	return func(subject string, ev []facts.Fact) *Script {
		f := firstFact(ev, "mssql.server_config")
		if f == nil {
			return nil
		}
		cur := f.Attributes["value_in_use"]
		if cur == "" {
			cur = "1"
		}
		ruleID := "db.mssql." + ruleKey
		return &Script{
			RuleID: ruleID, Subject: subject,
			Precheck: fmt.Sprintf("EXEC sp_configure %s;", sq(option)),
			Fix: fmt.Sprintf("EXEC sp_configure 'show advanced options', 1;\nRECONFIGURE;\nEXEC sp_configure %s, 0;\nRECONFIGURE;\nEXEC sp_configure 'show advanced options', 0;\nRECONFIGURE;", sq(option)),
			Verify:   fmt.Sprintf("SELECT name, value_in_use FROM sys.configurations WHERE name = %s;  -- 应为 0", sq(option)),
			Rollback: fmt.Sprintf("EXEC sp_configure 'show advanced options', 1;\nRECONFIGURE;\nEXEC sp_configure %s, %s;\nRECONFIGURE;\nEXEC sp_configure 'show advanced options', 0;\nRECONFIGURE;", sq(option), cur),
			Note:     note,
		}
	}
}
