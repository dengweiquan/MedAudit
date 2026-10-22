package remediation

import (
	"fmt"
	"sort"
	"strings"

	"medaudit/internal/facts"
)

func init() {
	generators["db.pg.superuser"] = pgSuperuser
	generators["db.pg.dangerous_role_attrs"] = pgDangerousAttrs
	generators["db.pg.public_db_create"] = pgPublicDBCreate
	generators["db.pg.public_writable"] = pgPublicWritable
	generators["db.pg.password_encryption_weak"] = pgAlterSystem("password_encryption", "scram-sha-256",
		"仅影响之后新设置/修改的口令，存量 md5 口令不会自动升级；建议配合口令轮换计划。改后执行 pg_reload_conf 即生效，无需重启。")
	generators["db.pg.listen_all"] = pgListenAll
	generators["db.pg.hba_trust"] = pgHBA("trust")
	generators["db.pg.hba_weak_method"] = pgHBA("weak")
	generators["db.pg.hba_open_network"] = pgHBA("open")
}

func pgRolesFact(ev []facts.Fact) *facts.Fact { return firstFact(ev, "pg.roles") }

func pgSuperuser(subject string, ev []facts.Fact) *Script {
	f := pgRolesFact(ev)
	if f == nil || f.Attributes["is_superuser"] != "true" {
		return nil
	}
	return &Script{
		RuleID: "db.pg.superuser", Subject: subject,
		Precheck: fmt.Sprintf("SELECT rolname, rolsuper FROM pg_roles WHERE rolname = %s;", sq(subject)),
		Fix:      fmt.Sprintf("ALTER ROLE %s NOSUPERUSER;", dq(subject)),
		Verify:   fmt.Sprintf("SELECT rolname, rolsuper FROM pg_roles WHERE rolname = %s;  -- rolsuper 应为 f", sq(subject)),
		Rollback: fmt.Sprintf("ALTER ROLE %s SUPERUSER;", dq(subject)),
		Note:     "已建立的会话保留超级权限直至重连；执行前确认该角色没有依赖超级权限的定时任务（如逻辑复制、扩展维护）。",
	}
}

// pgDangerousAttrs 按证据里实际为 true 的危险属性生成成对的 NO/正向命令。
func pgDangerousAttrs(subject string, ev []facts.Fact) *Script {
	f := pgRolesFact(ev)
	if f == nil {
		return nil
	}
	attrs := []struct{ key, no, yes string }{
		{"can_create_db", "NOCREATEDB", "CREATEDB"},
		{"can_create_role", "NOCREATEROLE", "CREATEROLE"},
		{"replication", "NOREPLICATION", "REPLICATION"},
		{"bypass_rls", "NOBYPASSRLS", "BYPASSRLS"},
	}
	var nos, yeses []string
	for _, a := range attrs {
		if f.Attributes[a.key] == "true" {
			nos = append(nos, a.no)
			yeses = append(yeses, a.yes)
		}
	}
	if len(nos) == 0 {
		return nil
	}
	return &Script{
		RuleID: "db.pg.dangerous_role_attrs", Subject: subject,
		Precheck: fmt.Sprintf("SELECT rolname, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls FROM pg_roles WHERE rolname = %s;", sq(subject)),
		Fix:      fmt.Sprintf("ALTER ROLE %s %s;", dq(subject), strings.Join(nos, " ")),
		Verify:   fmt.Sprintf("SELECT rolname, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls FROM pg_roles WHERE rolname = %s;  -- 上述属性应全为 f", sq(subject)),
		Rollback: fmt.Sprintf("ALTER ROLE %s %s;", dq(subject), strings.Join(yeses, " ")),
		Note:     "只回收证据中实际开启的危险属性，其余属性不动。REPLICATION 被回收会影响该角色的逻辑/物理复制连接。",
	}
}

func grantSuffix(f facts.Fact) string {
	if grantOpt(f) {
		return " WITH GRANT OPTION"
	}
	return ""
}

func pgPublicDBCreate(subject string, ev []facts.Fact) *Script {
	fs := privFacts(ev, "pg.db_privileges")
	if len(fs) == 0 {
		return nil
	}
	var fix, rb []string
	seen := map[string]bool{}
	for _, f := range fs {
		db := f.Attributes["database"]
		priv := f.Attributes["privilege"]
		if db == "" || priv == "" || seen[db+"|"+priv] {
			continue
		}
		seen[db+"|"+priv] = true
		fix = append(fix, fmt.Sprintf("REVOKE %s ON DATABASE %s FROM PUBLIC;", priv, dq(db)))
		rb = append(rb, fmt.Sprintf("GRANT %s ON DATABASE %s TO PUBLIC%s;", priv, dq(db), grantSuffix(f)))
	}
	if len(fix) == 0 {
		return nil
	}
	return &Script{
		RuleID: "db.pg.public_db_create", Subject: subject,
		Precheck: "SELECT datname, datacl FROM pg_database;  -- 查看各库 ACL 中 PUBLIC 的权限",
		Fix:      strings.Join(fix, "\n"),
		Verify:   fmt.Sprintf("SELECT has_database_privilege('PUBLIC', %s, 'CREATE');  -- 应为 f", sq(fs[0].Attributes["database"])),
		Rollback: strings.Join(rb, "\n"),
		Note:     "回收后普通用户在该库 public 模式下建表将依赖显式授权；历史已建对象不受影响。",
	}
}

func pgPublicWritable(subject string, ev []facts.Fact) *Script {
	var fix, rb, verifies []string
	// 模式级（CREATE on schema）
	type key struct{ db, obj, kind string }
	groups := map[key]struct {
		privs []string
		grant bool
	}{}
	add := func(db, obj, kind, priv string, grant bool) {
		k := key{db, obj, kind}
		g := groups[k]
		g.privs = append(g.privs, priv)
		g.grant = g.grant || grant
		groups[k] = g
	}
	for _, f := range privFacts(ev, "pg.schema_privileges") {
		add(f.Attributes["database"], f.Attributes["schema"], "schema", f.Attributes["privilege"], grantOpt(f))
	}
	for _, f := range privFacts(ev, "pg.object_privileges") {
		obj := f.Attributes["object"]
		if s := f.Attributes["schema"]; s != "" && obj != "" {
			obj = s + "." + obj
		}
		if obj == "" {
			obj = f.Scope
		}
		add(f.Attributes["database"], obj, "table", f.Attributes["privilege"], grantOpt(f))
	}
	if len(groups) == 0 {
		return nil
	}
	var keys []key
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].obj < keys[j].obj })
	for _, k := range keys {
		g := groups[k]
		privs := strings.Join(dedupeSorted(g.privs), ", ")
		gs := ""
		if g.grant {
			gs = " WITH GRANT OPTION"
		}
		switch k.kind {
		case "schema":
			fix = append(fix, fmt.Sprintf("REVOKE %s ON SCHEMA %s FROM PUBLIC;", privs, dq(lastPart(k.obj))))
			rb = append(rb, fmt.Sprintf("GRANT %s ON SCHEMA %s TO PUBLIC%s;", privs, dq(lastPart(k.obj)), gs))
			verifies = append(verifies, fmt.Sprintf("SELECT has_schema_privilege('PUBLIC', %s, %s);  -- 应为 f（在库 %s 中执行）", sq(lastPart(k.obj)), sq(firstOf(g.privs)), k.db))
		default:
			tbl := dq(k.obj)
			if parts := strings.SplitN(k.obj, ".", 2); len(parts) == 2 {
				tbl = dq(parts[0]) + "." + dq(parts[1])
			}
			fix = append(fix, fmt.Sprintf("REVOKE %s ON TABLE %s FROM PUBLIC;", privs, tbl))
			rb = append(rb, fmt.Sprintf("GRANT %s ON TABLE %s TO PUBLIC%s;", privs, tbl, gs))
			verifies = append(verifies, fmt.Sprintf("SELECT has_table_privilege('PUBLIC', %s, %s);  -- 应为 f（在库 %s 中执行）", sq(k.obj), sq(firstOf(g.privs)), k.db))
		}
	}
	return &Script{
		RuleID: "db.pg.public_writable", Subject: subject,
		Precheck: "SELECT datname FROM pg_database;  -- 先确认目标库，下列命令须连接到对应数据库执行",
		Fix:      strings.Join(fix, "\n"),
		Verify:   strings.Join(verifies, "\n"),
		Rollback: strings.Join(rb, "\n"),
		Note:     "对象/模式授权按库存储：每组命令须在对应数据库中执行（已在 Verify 中标注库名）。回收 PUBLIC 不影响已显式授权给具体角色的权限。",
	}
}

func firstOf(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func lastPart(s string) string {
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[i+1:]
	}
	return s
}

func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// pgAlterSystem ALTER SYSTEM 型设置（证据 pg.settings 的 name/value）。
func pgAlterSystem(name, want, note string) generator {
	return func(subject string, ev []facts.Fact) *Script {
		f := firstFact(ev, "pg.settings")
		if f == nil {
			return nil
		}
		cur := f.Attributes["value"]
		if cur == "" {
			cur = f.Attributes["setting"]
		}
		if cur == "" {
			return nil
		}
		ruleID := "db.pg.password_encryption_weak"
		return &Script{
			RuleID: ruleID, Subject: subject,
			Precheck: fmt.Sprintf("SHOW %s;  -- 当前应为 %s", name, cur),
			Fix:      fmt.Sprintf("ALTER SYSTEM SET %s = %s;\nSELECT pg_reload_conf();", name, sq(want)),
			Verify:   fmt.Sprintf("SHOW %s;  -- 应为 %s", name, want),
			Rollback: fmt.Sprintf("ALTER SYSTEM SET %s = %s;\nSELECT pg_reload_conf();", name, sq(cur)),
			Note:     note,
		}
	}
}

func pgListenAll(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "pg.settings")
	if f == nil {
		return nil
	}
	cur := f.Attributes["value"]
	if cur == "" {
		cur = f.Attributes["setting"]
	}
	if cur == "" {
		return nil
	}
	return &Script{
		RuleID: "db.pg.listen_all", Subject: subject,
		Precheck: "SHOW listen_addresses;",
		Fix:      "ALTER SYSTEM SET listen_addresses = 'localhost';",
		Verify:   "SHOW listen_addresses;  -- 重启后应为 localhost",
		Rollback: fmt.Sprintf("ALTER SYSTEM SET listen_addresses = %s;", sq(cur)),
		Note:     "listen_addresses 只能改后**重启实例**才生效；'localhost' 仅适合应用与库同机的部署——应用在其它主机时应改为具体内网网卡地址（或保留 * 并收紧 pg_hba 与防火墙），按现场拓扑调整本脚本再执行。",
	}
}

// pgHBA 指导型脚本：给出确切行、替换行与重载/回滚。证据 pg.hba 事实属性：
// line_number/type/database/user/address/auth_method（以采集模板为准，缺失则降级为整表定位）。
func pgHBA(kind string) generator {
	return func(subject string, ev []facts.Fact) *Script {
		f := firstFact(ev, "pg.hba")
		if f == nil {
			return nil
		}
		a := f.Attributes
		ruleID := map[string]string{
			"trust": "db.pg.hba_trust", "weak": "db.pg.hba_weak_method", "open": "db.pg.hba_open_network",
		}[kind]
		method := a["auth_method"]
		if method == "" {
			method = a["method"]
		}
		addr := a["address"]
		if a["netmask"] != "" {
			addr += "（掩码 " + a["netmask"] + "）"
		}
		lineDesc := fmt.Sprintf("第 %s 行：type=%s database=%s user=%s address=%s method=%s",
			a["line_number"], a["conn_type"], a["databases"], f.Subject, addr, method)
		var step2, rbStep string
		if kind == "open" {
			step2 = fmt.Sprintf("认证方式（%s）保持不变，将地址由 %s 收窄为应用实际网段（例如 172.16.1.0/24）", method, addr)
			rbStep = fmt.Sprintf("将该行（%s）的地址改回 %s", lineDesc, addr)
		} else {
			step2 = fmt.Sprintf("将其认证方式由 %s 改为 scram-sha-256", method)
			rbStep = fmt.Sprintf("将该行（%s）的认证方式改回 %s", lineDesc, method)
		}
		precheck := "SELECT line_number, type, database, \"user\", address, auth_method, error FROM pg_hba_file_rules ORDER BY line_number;"
		fix := fmt.Sprintf(`-- 指导型整改（pg_hba.conf 为文件，无单条 SQL 修复）：
-- 1) 在 pg_hba.conf 中定位该行（%s）；
-- 2) %s，保存；
-- 3) 执行下面一行重载（或 pg_ctl reload）：
SELECT pg_reload_conf();`, lineDesc, step2)
		rollback := fmt.Sprintf(`-- 回滚：%s，保存后执行：
SELECT pg_reload_conf();`, rbStep)
		return &Script{
			RuleID: ruleID, Subject: subject,
			Precheck: precheck,
			Fix:      fix,
			Verify:   "SELECT line_number, type, database, \"user\", address, auth_method FROM pg_hba_file_rules ORDER BY line_number;  -- 目标行应已更新；另开新连接验证登录行为",
			Rollback: rollback,
			Note:     "pg_hba 按行序首中匹配：改动只影响新连接；trust 改为 scram-sha-256 前先确认该来源的账号已设置口令（存量无口令账号将无法登录），这正是本条风险的处置顺序。",
		}
	}
}
