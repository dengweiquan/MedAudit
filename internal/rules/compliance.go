package rules

import "sort"

// 合规条款映射：每条内置规则对应的等保 2.0（GB/T 22239-2019）第三级
// 「安全计算环境」条款。报告与 Web 用它把技术问题翻译成院方/测评机构
// 关心的条款口径。条款文本为要点概述，正式引用以标准原文为准。

// ComplianceFramework 映射所依据的标准。
const ComplianceFramework = "等保 2.0（GB/T 22239-2019）第三级 · 安全计算环境"

// Control 一个标准条款。
type Control struct {
	ID    string `json:"id"`    // 如 8.1.4.2 d)
	Group string `json:"group"` // 如 访问控制
	Title string `json:"title"` // 条款要点
}

var controls = map[string]Control{
	"8.1.4.1a": {"8.1.4.1 a)", "身份鉴别", "身份标识唯一，鉴别信息有复杂度要求并定期更换"},
	"8.1.4.1b": {"8.1.4.1 b)", "身份鉴别", "登录失败处理、限制非法登录次数、连接超时自动退出"},
	"8.1.4.1c": {"8.1.4.1 c)", "身份鉴别", "远程管理时防止鉴别信息在网络传输中被窃听"},
	"8.1.4.2a": {"8.1.4.2 a)", "访问控制", "对登录的用户分配账户和权限"},
	"8.1.4.2b": {"8.1.4.2 b)", "访问控制", "重命名或删除默认账户，修改默认账户的默认口令"},
	"8.1.4.2c": {"8.1.4.2 c)", "访问控制", "及时删除或停用多余、过期账户，避免共享账户"},
	"8.1.4.2d": {"8.1.4.2 d)", "访问控制", "授予管理用户所需的最小权限，实现权限分离"},
	"8.1.4.2e": {"8.1.4.2 e)", "访问控制", "由授权主体配置访问控制策略"},
	"8.1.4.4a": {"8.1.4.4 a)", "入侵防范", "遵循最小安装原则，仅安装需要的组件和应用程序"},
	"8.1.4.4b": {"8.1.4.4 b)", "入侵防范", "关闭不需要的系统服务、默认共享和高危端口"},
	"8.1.4.4c": {"8.1.4.4 c)", "入侵防范", "限制管理终端的接入方式或网络地址范围"},
	"8.1.4.8a": {"8.1.4.8 a)", "数据保密性", "采用密码技术保证重要数据在传输过程中的保密性"},
	"8.1.4.8b": {"8.1.4.8 b)", "数据保密性", "采用密码技术保证重要数据在存储过程中的保密性"},
}

var ruleControls = map[string][]string{
	// SQL Server
	"db.mssql.adhoc_distributed": {"8.1.4.4b"},
	"db.mssql.clr_enabled":       {"8.1.4.4a"},
	"db.mssql.control_server":    {"8.1.4.2d"},
	"db.mssql.cross_db_chaining": {"8.1.4.2d"},
	"db.mssql.sysadmin":          {"8.1.4.2d"},
	"db.mssql.xp_cmdshell":       {"8.1.4.4b", "8.1.4.2d"},
	// MySQL
	"db.mysql.general_log_on":  {"8.1.4.8b"},
	"db.mysql.global_admin":    {"8.1.4.2d"},
	"db.mysql.grant_option":    {"8.1.4.2d", "8.1.4.2e"},
	"db.mysql.local_infile":    {"8.1.4.4b"},
	"db.mysql.name_resolve_on": {"8.1.4.4c"},
	"db.mysql.remote_no_tls":   {"8.1.4.1c", "8.1.4.8a"},
	// Oracle
	"db.oracle.any_privilege":           {"8.1.4.2d"},
	"db.oracle.cdb_dba_in_pdb":          {"8.1.4.2d"},
	"db.oracle.dba_role":                {"8.1.4.2d"},
	"db.oracle.default_account_open":    {"8.1.4.2b"},
	"db.oracle.grant_option_spread":     {"8.1.4.2d", "8.1.4.2e"},
	"db.oracle.profile_password_policy": {"8.1.4.1a", "8.1.4.1b"},
	"db.oracle.public_object_grant":     {"8.1.4.2a", "8.1.4.2d"},
	"db.oracle.sys_schema_grant":        {"8.1.4.2d"},
	"db.oracle.sysdba_pwfile":           {"8.1.4.2d"},
	// PostgreSQL
	"db.pg.dangerous_role_attrs":     {"8.1.4.2d"},
	"db.pg.hba_open_network":         {"8.1.4.4c"},
	"db.pg.hba_trust":                {"8.1.4.1a"},
	"db.pg.hba_weak_method":          {"8.1.4.1a", "8.1.4.1c"},
	"db.pg.listen_all":               {"8.1.4.4c"},
	"db.pg.password_encryption_weak": {"8.1.4.8b"},
	"db.pg.public_db_create":         {"8.1.4.2a", "8.1.4.2d"},
	"db.pg.public_writable":          {"8.1.4.2a", "8.1.4.2d"},
	"db.pg.superuser":                {"8.1.4.2d"},
	// IIS
	"mw.iis.anon_open":      {"8.1.4.1a", "8.1.4.2a"},
	"mw.iis.apppool_system": {"8.1.4.2d"},
	"mw.iis.default_site":   {"8.1.4.2b", "8.1.4.4a"},
	"mw.iis.plain_binding":  {"8.1.4.8a"},
	// Nginx
	"mw.nginx.autoindex":       {"8.1.4.4b"},
	"mw.nginx.config_writable": {"8.1.4.2d"},
	"mw.nginx.plain_listener":  {"8.1.4.8a"},
	"mw.nginx.run_as_root":     {"8.1.4.2d"},
	"mw.nginx.tls_weak":        {"8.1.4.8a"},
	// Tomcat
	"mw.tomcat.config_writable":  {"8.1.4.2d"},
	"mw.tomcat.console_admin":    {"8.1.4.2d"},
	"mw.tomcat.manager_deployed": {"8.1.4.4a", "8.1.4.4c"},
	"mw.tomcat.plain_listener":   {"8.1.4.8a"},
	"mw.tomcat.run_as_root":      {"8.1.4.2d"},
	"mw.tomcat.sample_apps":      {"8.1.4.4a"},
	"mw.tomcat.tls_weak":         {"8.1.4.8a"},
	// WebLogic
	"mw.weblogic.config_writable":  {"8.1.4.2d"},
	"mw.weblogic.console_deployed": {"8.1.4.4a", "8.1.4.4c"},
	"mw.weblogic.dev_mode":         {"8.1.4.4a"},
	"mw.weblogic.plain_listener":   {"8.1.4.8a"},
	"mw.weblogic.run_as_root":      {"8.1.4.2d"},
	// HP-UX
	"os.hpux.inetd_risky_service":   {"8.1.4.4b"},
	"os.hpux.multiple_uid0":         {"8.1.4.1a", "8.1.4.2c"},
	"os.hpux.setuid_unexpected":     {"8.1.4.2d"},
	"os.hpux.sudo_all":              {"8.1.4.2d"},
	"os.hpux.weak_password_store":   {"8.1.4.8b"},
	"os.hpux.writable_service_file": {"8.1.4.2d"},
	// Linux
	"os.linux.high_capabilities":     {"8.1.4.2d"},
	"os.linux.root_mismatch":         {"8.1.4.2d"},
	"os.linux.sudo_all":              {"8.1.4.2d"},
	"os.linux.sudo_nopasswd_all":     {"8.1.4.1a", "8.1.4.2d"},
	"os.linux.writable_service_file": {"8.1.4.2d"},
	// Windows
	"os.windows.svc_account_mismatch":    {"8.1.4.2d"},
	"os.windows.unexpected_admin":        {"8.1.4.2c", "8.1.4.2d"},
	"os.windows.writable_service_binary": {"8.1.4.2d"},
}

// ControlsFor 返回规则对应的条款（按条款号排序）；未映射返回 nil。
func ControlsFor(ruleID string) []Control {
	keys := ruleControls[ruleID]
	out := make([]Control, 0, len(keys))
	for _, k := range keys {
		if c, ok := controls[k]; ok {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
