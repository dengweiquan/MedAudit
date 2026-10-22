package remediation

import (
	"fmt"
	"strings"

	"medaudit/internal/facts"
)

func init() {
	generators["db.oracle.dba_role"] = oraDBARole
	generators["db.oracle.sysdba_pwfile"] = oraSysdbaPwfile
	generators["db.oracle.any_privilege"] = oraAnyPrivilege
	generators["db.oracle.cdb_dba_in_pdb"] = oraCDBDBA
	generators["db.oracle.public_object_grant"] = oraPublicObjectGrant
	generators["db.oracle.sys_schema_grant"] = oraSysSchemaGrant
	generators["db.oracle.grant_option_spread"] = oraGrantOptionSpread
	generators["db.oracle.default_account_open"] = oraDefaultAccountOpen
	generators["db.oracle.profile_password_policy"] = oraProfilePolicy
}

// splitScopeOwner 按第一个点拆 OWNER.OBJECT（对象名可含点，如 Java 资源路径）。
func splitScopeOwner(scope string) (owner, object string, ok bool) {
	i := strings.Index(scope, ".")
	if i <= 0 || i == len(scope)-1 {
		return "", "", false
	}
	return scope[:i], scope[i+1:], true
}

func oraDBARole(subject string, ev []facts.Fact) *Script {
	for _, e := range roleEdges(ev) {
		if e.Subject == subject && strings.EqualFold(e.PermissionPath[0], "DBA") {
			admin := ""
			if grantOpt(e) {
				admin = " WITH ADMIN OPTION"
			}
			return &Script{
				RuleID: "db.oracle.dba_role", Subject: subject,
				Precheck: fmt.Sprintf("SELECT granted_role, admin_option FROM dba_role_privs WHERE grantee = %s AND granted_role = 'DBA';", sq(subject)),
				Fix:      fmt.Sprintf("REVOKE DBA FROM %s;", dq(subject)),
				Verify:   fmt.Sprintf("SELECT * FROM dba_role_privs WHERE grantee = %s AND granted_role = 'DBA';  -- 应为空", sq(subject)),
				Rollback: fmt.Sprintf("GRANT DBA TO %s%s;", dq(subject), admin),
				Note:     "回收 DBA 角色会同时收回其打包的全部系统与对象权限；该账号若承载应用运行，应改为按对象清单新建最小权限角色后切换。",
			}
		}
	}
	return nil
}

func oraSysdbaPwfile(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "ora.pwfile_users")
	if f == nil {
		return nil
	}
	return &Script{
		RuleID: "db.oracle.sysdba_pwfile", Subject: subject,
		Precheck: fmt.Sprintf("SELECT username, sysdba, sysoper FROM v$pwfile_users WHERE username = %s;", sq(subject)),
		Fix:      fmt.Sprintf("REVOKE SYSDBA FROM %s;", dq(subject)),
		Verify:   fmt.Sprintf("SELECT * FROM v$pwfile_users WHERE username = %s;  -- 应为空或 SYSDBA 列为 FALSE", sq(subject)),
		Rollback: fmt.Sprintf("GRANT SYSDBA TO %s;", dq(subject)),
		Note:     "SYSDBA 回收后该用户仍可普通登录；远程 SYSDBA 登录依赖口令文件，回收会影响异地运维通道，先确认带外运维方式。回滚重新授予需要当前执行者本身持有 SYSDBA。",
	}
}

func oraAnyPrivilege(subject string, ev []facts.Fact) *Script {
	fs := append(privFacts(ev, "ora.sys_privs"), privFacts(ev, "ora.cdb_sys_privs")...)
	if len(fs) == 0 {
		return nil
	}
	var fix, rb []string
	seen := map[string]bool{}
	for _, f := range fs {
		priv := f.Attributes["privilege"]
		if !strings.Contains(strings.ToUpper(priv), " ANY ") && !strings.HasSuffix(strings.ToUpper(priv), " ANY") && !strings.HasPrefix(strings.ToUpper(priv), "ANY ") {
			// 规则只对 ANY 类系统权限命中；非 ANY 的证据不生成命令
			continue
		}
		if seen[priv] {
			continue
		}
		seen[priv] = true
		fix = append(fix, fmt.Sprintf("REVOKE %s FROM %s;", priv, dq(subject)))
		admin := ""
		if grantOpt(f) {
			admin = " WITH ADMIN OPTION"
		}
		rb = append(rb, fmt.Sprintf("GRANT %s TO %s%s;", priv, dq(subject), admin))
	}
	if len(fix) == 0 {
		return nil
	}
	return &Script{
		RuleID: "db.oracle.any_privilege", Subject: subject,
		Precheck: fmt.Sprintf("SELECT privilege, admin_option FROM dba_sys_privs WHERE grantee = %s;", sq(subject)),
		Fix:      strings.Join(fix, "\n"),
		Verify:   fmt.Sprintf("SELECT privilege FROM dba_sys_privs WHERE grantee = %s AND privilege LIKE '%%ANY%%';  -- 应为空", sq(subject)),
		Rollback: strings.Join(rb, "\n"),
		Note:     "ANY 类系统权限跨越全部模式边界；若主体是角色（如 DBA 角色本体），回收会影响全部被授予该角色的用户——属角色定义的应改走基线备案。",
	}
}

func oraCDBDBA(subject string, ev []facts.Fact) *Script {
	// CDB 场景：授权的容器上下文在 cdb_role_privs 事实里；无确切容器信息时给指导型脚本。
	for _, e := range roleEdges(ev) {
		if e.Subject != subject {
			continue
		}
		cont := e.Attributes["container"]
		if cont == "" {
			cont = e.Attributes["con_name"]
		}
		admin := ""
		if grantOpt(e) {
			admin = " WITH ADMIN OPTION"
		}
		if cont != "" {
			return &Script{
				RuleID: "db.oracle.cdb_dba_in_pdb", Subject: subject,
				Precheck: fmt.Sprintf("SELECT grantee, granted_role, common FROM cdb_role_privs WHERE grantee = %s;", sq(subject)),
				Fix:      fmt.Sprintf("ALTER SESSION SET CONTAINER = %s;\nREVOKE %s FROM %s;", cont, e.PermissionPath[0], dq(subject)),
				Verify:   fmt.Sprintf("SELECT * FROM cdb_role_privs WHERE grantee = %s AND granted_role = %s;  -- 该容器内应为空", sq(subject), sq(e.PermissionPath[0])),
				Rollback: fmt.Sprintf("ALTER SESSION SET CONTAINER = %s;\nGRANT %s TO %s%s;", cont, e.PermissionPath[0], dq(subject), admin),
				Note:     "CDB/PDB 分层授权：回收只作用于证据所在容器，不影响该主体在其它容器的同名授权。",
			}
		}
	}
	return &Script{
		RuleID: "db.oracle.cdb_dba_in_pdb", Subject: subject,
		Precheck: "SELECT grantee, granted_role, common, con_id FROM cdb_role_privs WHERE grantee = '" + strings.ReplaceAll(subject, "'", "''") + "';",
		Fix: "-- 指导型整改：证据未带确切容器名。先按 Precheck 结果确认授权所在容器，\n" +
			"-- 再在该容器内执行：ALTER SESSION SET CONTAINER = <容器>; REVOKE <角色> FROM \"" + subject + "\";",
		Verify:   "SELECT * FROM cdb_role_privs WHERE grantee = '" + strings.ReplaceAll(subject, "'", "''") + "';  -- 目标容器行应消失",
		Rollback: "-- 回滚：在同一容器内 GRANT <角色> TO \"" + subject + "\";（原带 ADMIN OPTION 时补 WITH ADMIN OPTION）",
		Note:     "跨容器授权的切断点必须落到具体容器，笼统在 CDB$ROOT 回收可能误伤公共授权。",
	}
}

// oraObjectGrant tab_privs 类三规则共用构造：fixVerb 区分面向 PUBLIC/指定主体。
func oraTabPrivScript(ruleID, subject string, f facts.Fact, grantee string) *Script {
	owner, object, ok := splitScopeOwner(f.Scope)
	priv := f.Attributes["privilege"]
	if !ok || priv == "" {
		return nil
	}
	target := grantee
	if grantee == "PUBLIC" {
		target = "PUBLIC"
	} else {
		target = dq(grantee)
	}
	obj := dq(owner) + "." + dq(object)
	return &Script{
		RuleID: ruleID, Subject: subject, Scope: f.Scope,
		Precheck: fmt.Sprintf("SELECT privilege, grantable FROM dba_tab_privs WHERE grantee = %s AND owner = %s AND table_name = %s;",
			sq(grantee), sq(owner), sq(object)),
		Fix:      fmt.Sprintf("REVOKE %s ON %s FROM %s;", priv, obj, target),
		Verify:   fmt.Sprintf("SELECT * FROM dba_tab_privs WHERE grantee = %s AND owner = %s AND table_name = %s AND privilege = %s;  -- 应为空", sq(grantee), sq(owner), sq(object), sq(priv)),
		Rollback: fmt.Sprintf("GRANT %s ON %s TO %s%s;", priv, obj, target, map[bool]string{true: " WITH GRANT OPTION", false: ""}[grantOpt(f)]),
	}
}

func oraPublicObjectGrant(subject string, ev []facts.Fact) *Script {
	for _, f := range privFacts(ev, "ora.tab_privs") {
		if f.Subject == "PUBLIC" {
			if s := oraTabPrivScript("db.oracle.public_object_grant", subject, f, "PUBLIC"); s != nil {
				s.Note = "授予 PUBLIC 等于授予全部现存与未来用户；回收后依赖隐式公共权限的应用账号会报 ORA-00942/01031，应改授给专用角色。"
				return s
			}
		}
	}
	for _, f := range privFacts(ev, "ora.cdb_tab_privs") {
		if f.Subject == "PUBLIC" {
			if s := oraTabPrivScript("db.oracle.public_object_grant", subject, f, "PUBLIC"); s != nil {
				return s
			}
		}
	}
	return nil
}

func oraSysSchemaGrant(subject string, ev []facts.Fact) *Script {
	for _, f := range append(privFacts(ev, "ora.tab_privs"), privFacts(ev, "ora.cdb_tab_privs")...) {
		owner, _, ok := splitScopeOwner(f.Scope)
		if ok && (owner == "SYS" || owner == "SYSTEM") && f.Subject == subject {
			if s := oraTabPrivScript("db.oracle.sys_schema_grant", subject, f, subject); s != nil {
				s.Note = "SYS/SYSTEM 模式对象是数据字典与系统包，外部持有其权限可绕过常规审计面；确属厂商/平台组件账号的应走基线备案逐项登记。"
				return s
			}
		}
	}
	return nil
}

func oraGrantOptionSpread(subject string, ev []facts.Fact) *Script {
	for _, f := range append(privFacts(ev, "ora.tab_privs"), privFacts(ev, "ora.cdb_tab_privs")...) {
		if !grantOpt(f) || f.Subject != subject {
			continue
		}
		owner, object, ok := splitScopeOwner(f.Scope)
		priv := f.Attributes["privilege"]
		if !ok || priv == "" {
			continue
		}
		obj := dq(owner) + "." + dq(object)
		return &Script{
			RuleID: "db.oracle.grant_option_spread", Subject: subject, Scope: f.Scope,
			Precheck: fmt.Sprintf("SELECT privilege, grantable FROM dba_tab_privs WHERE grantee = %s AND owner = %s AND table_name = %s;", sq(subject), sq(owner), sq(object)),
			Fix: fmt.Sprintf("REVOKE %s ON %s FROM %s;\nGRANT %s ON %s TO %s;",
				priv, obj, dq(subject), priv, obj, dq(subject)),
			Verify:   fmt.Sprintf("SELECT grantable FROM dba_tab_privs WHERE grantee = %s AND owner = %s AND table_name = %s AND privilege = %s;  -- 应为 NO 且行仍在", sq(subject), sq(owner), sq(object), sq(priv)),
			Rollback: fmt.Sprintf("GRANT %s ON %s TO %s WITH GRANT OPTION;", priv, obj, dq(subject)),
			Note:     "修复分两步：先回收再无转授重授，本人权限不中断（两句须同会话连续执行）；已被该主体转授出去的下游授权不会自动消失，需另行按 dba_tab_privs 的 grantor 链排查。",
		}
	}
	return nil
}

func oraDefaultAccountOpen(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "ora.users")
	if f == nil {
		f = firstFact(ev, "ora.cdb_users")
	}
	if f == nil || !strings.EqualFold(f.Attributes["account_status"], "OPEN") {
		return nil
	}
	return &Script{
		RuleID: "db.oracle.default_account_open", Subject: subject,
		Precheck: fmt.Sprintf("SELECT username, account_status FROM dba_users WHERE username = %s;", sq(subject)),
		Fix:      fmt.Sprintf("ALTER USER %s ACCOUNT LOCK;", dq(subject)),
		Verify:   fmt.Sprintf("SELECT account_status FROM dba_users WHERE username = %s;  -- 应为 LOCKED", sq(subject)),
		Rollback: fmt.Sprintf("ALTER USER %s ACCOUNT UNLOCK;", dq(subject)),
		Note:     "默认/示例账号多带公开已知口令，锁定不改口令、解锁即恢复，属可逆处置；若该账号实际承载组件（如某些 APEX/OWB 场景），先在组件文档核对再锁。",
	}
}

var oraProfileRecommended = map[string]string{
	"PASSWORD_LIFE_TIME":    "90",
	"FAILED_LOGIN_ATTEMPTS": "10",
	"PASSWORD_REUSE_MAX":    "10",
	"PASSWORD_REUSE_TIME":   "365",
	"PASSWORD_GRACE_TIME":   "7",
}

func oraProfilePolicy(subject string, ev []facts.Fact) *Script {
	var fix, rb []string
	seen := map[string]bool{}
	for _, f := range ev {
		if f.Source != "ora.profiles" {
			continue
		}
		res := f.Attributes["resource"]
		rec, ok := oraProfileRecommended[res]
		if !ok || seen[res] || !strings.EqualFold(f.Attributes["limit"], "UNLIMITED") {
			continue
		}
		seen[res] = true
		fix = append(fix, fmt.Sprintf("ALTER PROFILE %s LIMIT %s %s;", dq(subject), res, rec))
		rb = append(rb, fmt.Sprintf("ALTER PROFILE %s LIMIT %s UNLIMITED;", dq(subject), res))
	}
	if len(fix) == 0 {
		return nil
	}
	return &Script{
		RuleID: "db.oracle.profile_password_policy", Subject: subject,
		Precheck: fmt.Sprintf("SELECT resource_name, limit FROM dba_profiles WHERE profile = %s AND resource_type = 'PASSWORD';", sq(subject)),
		Fix:      strings.Join(fix, "\n"),
		Verify:   fmt.Sprintf("SELECT resource_name, limit FROM dba_profiles WHERE profile = %s AND resource_type = 'PASSWORD';  -- 上述项应为新数值", sq(subject)),
		Rollback: strings.Join(rb, "\n"),
		Note:     "Fix 中的数值是等保常用建议值，可按院内口令制度调整后再执行；回滚恢复生成时捕获的原值（UNLIMITED）。改 profile 只影响之后登录与改密，不强制现存会话。",
	}
}
