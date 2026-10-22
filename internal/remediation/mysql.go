package remediation

import (
	"fmt"
	"sort"
	"strings"

	"medaudit/internal/facts"
)

func init() {
	generators["db.mysql.global_admin"] = myGlobalAdmin
	generators["db.mysql.grant_option"] = myGrantOption
	generators["db.mysql.remote_no_tls"] = myRemoteNoTLS
	generators["db.mysql.local_infile"] = myServerVar("db.mysql.local_infile", "local_infile", "OFF",
		"local_infile 允许 LOAD DATA LOCAL 把客户端文件读入服务端，存在文件读取风险。SET PERSIST 重启后仍生效；老版本不支持 SET PERSIST 时改用 SET GLOBAL 并写入 my.cnf。")
	generators["db.mysql.general_log_on"] = myServerVar("db.mysql.general_log_on", "general_log", "OFF",
		"通用查询日志记录全部语句（含敏感数据）且消耗 IO。SET PERSIST 重启后仍生效；关闭前确认无审计合规要求依赖该日志。")
	generators["db.mysql.name_resolve_on"] = myServerVar("db.mysql.name_resolve_on", "skip_name_resolve", "ON",
		"skip_name_resolve 关闭主机名反向解析：授权按 IP 匹配，避免 DNS 欺骗与解析超时。开启后基于主机名的授权条目（如 'user'@'appserver'）将失效，执行前先用 Precheck 排查这类条目。")
}

// groupPrivByScope 把授权事实按 scope 分组：priv 列表（去重排序）+ 是否任一带 GRANT OPTION。
func groupPrivByScope(fs []facts.Fact) map[string]struct {
	privs []string
	grant bool
} {
	groups := map[string]map[string]bool{}
	grant := map[string]bool{}
	for _, f := range fs {
		if groups[f.Scope] == nil {
			groups[f.Scope] = map[string]bool{}
		}
		groups[f.Scope][f.Attributes["privilege"]] = true
		if grantOpt(f) {
			grant[f.Scope] = true
		}
	}
	out := map[string]struct {
		privs []string
		grant bool
	}{}
	for scope, set := range groups {
		var ps []string
		for p := range set {
			ps = append(ps, p)
		}
		sort.Strings(ps)
		out[scope] = struct {
			privs []string
			grant bool
		}{ps, grant[scope]}
	}
	return out
}

func sortedScopes(m map[string]struct {
	privs []string
	grant bool
}) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func myGlobalAdmin(subject string, ev []facts.Fact) *Script {
	fs := privFacts(ev, "")
	if len(fs) == 0 {
		return nil
	}
	acct := myAcct(subject)
	groups := groupPrivByScope(fs)
	var fix, rb, scope0 []string
	for _, scope := range sortedScopes(groups) {
		g := groups[scope]
		privs := strings.Join(g.privs, ", ")
		fix = append(fix, fmt.Sprintf("REVOKE %s ON %s FROM %s;", privs, scope, acct))
		grant := fmt.Sprintf("GRANT %s ON %s TO %s", privs, scope, acct)
		if g.grant {
			grant += " WITH GRANT OPTION"
		}
		rb = append(rb, grant+";")
		scope0 = append(scope0, scope)
	}
	return &Script{
		RuleID: "db.mysql.global_admin", Subject: subject, Scope: strings.Join(scope0, ","),
		Precheck: fmt.Sprintf("SHOW GRANTS FOR %s;", acct),
		Fix:      strings.Join(fix, "\n"),
		Verify:   fmt.Sprintf("SHOW GRANTS FOR %s;  -- 结果中不应再出现上述全局权限", acct),
		Rollback: strings.Join(rb, "\n"),
		Note:     "REVOKE 立即生效于新会话；已建立的会话保留权限直至重连。若该账号确为运维管理账号，应改走基线备案而非直接回收。",
	}
}

func myGrantOption(subject string, ev []facts.Fact) *Script {
	var fs []facts.Fact
	for _, f := range privFacts(ev, "") {
		if grantOpt(f) {
			fs = append(fs, f)
		}
	}
	if len(fs) == 0 {
		return nil
	}
	acct := myAcct(subject)
	groups := groupPrivByScope(fs)
	var fix, rb, scopes []string
	for _, scope := range sortedScopes(groups) {
		g := groups[scope]
		fix = append(fix, fmt.Sprintf("REVOKE GRANT OPTION ON %s FROM %s;", scope, acct))
		rb = append(rb, fmt.Sprintf("GRANT %s ON %s TO %s WITH GRANT OPTION;", strings.Join(g.privs, ", "), scope, acct))
		scopes = append(scopes, scope)
	}
	return &Script{
		RuleID: "db.mysql.grant_option", Subject: subject, Scope: strings.Join(scopes, ","),
		Precheck: fmt.Sprintf("SHOW GRANTS FOR %s;", acct),
		Fix:      strings.Join(fix, "\n"),
		Verify:   fmt.Sprintf("SHOW GRANTS FOR %s;  -- 相关授权行不应再带 WITH GRANT OPTION", acct),
		Rollback: strings.Join(rb, "\n"),
		Note:     "只剥离转授能力，本人原有权限不变；依赖该账号向下分发权限的流程会受影响，执行前确认。",
	}
}

func myRemoteNoTLS(subject string, ev []facts.Fact) *Script {
	if firstFact(ev, "mysql.account_tls") == nil {
		return nil
	}
	acct := myAcct(subject)
	return &Script{
		RuleID: "db.mysql.remote_no_tls", Subject: subject,
		Precheck: fmt.Sprintf("SELECT user, host, ssl_type FROM mysql.user WHERE user=%s AND host=%s;",
			sq(mustUser(subject)), sq(mustHost(subject))),
		Fix:      fmt.Sprintf("ALTER USER %s REQUIRE SSL;", acct),
		Verify:   fmt.Sprintf("SELECT user, host, ssl_type FROM mysql.user WHERE user=%s AND host=%s;  -- ssl_type 应为 ANY", sq(mustUser(subject)), sq(mustHost(subject))),
		Rollback: fmt.Sprintf("ALTER USER %s REQUIRE NONE;", acct),
		Note:     "仅约束新连接；客户端未启用 TLS 时改后将连不上，先通知应用侧。若有证书绑定需求可进一步用 REQUIRE X509/SUBJECT，本脚本按最小改动用 REQUIRE SSL。",
	}
}

func mustUser(subject string) string { u, _, _ := splitAcct(subject); return u }
func mustHost(subject string) string { _, h, _ := splitAcct(subject); return h }

// myServerVar SET PERSIST 型全局变量（证据为 mysql.server_config 的 name/value 事实）。
// want 为目标值；回滚恢复证据捕获的当前值。
func myServerVar(ruleID, name, want, note string) generator {
	return func(subject string, ev []facts.Fact) *Script {
		f := firstFact(ev, "mysql.server_config")
		if f == nil {
			for i := range ev {
				if strings.EqualFold(ev[i].Attributes["name"], name) {
					f = &ev[i]
					break
				}
			}
		}
		if f == nil {
			return nil
		}
		cur := f.Attributes["value"]
		if cur == "" {
			return nil
		}
		pre := fmt.Sprintf("SELECT @@GLOBAL.%s;  -- 当前应为 %s", name, cur)
		if ruleID == "db.mysql.name_resolve_on" {
			pre += "\nSELECT user, host FROM mysql.user WHERE host NOT LIKE '%\\%%' AND host NOT IN ('localhost','127.0.0.1','::1');  -- 基于主机名的授权条目（开启后失效）"
		}
		return &Script{
			RuleID: ruleID, Subject: subject,
			Precheck: pre,
			Fix:      fmt.Sprintf("SET PERSIST %s = %s;", name, want),
			Verify:   fmt.Sprintf("SELECT @@GLOBAL.%s;  -- 应为 %s", name, want),
			Rollback: fmt.Sprintf("SET PERSIST %s = %s;", name, cur),
			Note:     note,
		}
	}
}
