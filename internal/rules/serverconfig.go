package rules

import (
	"fmt"
	"strings"

	"medaudit/internal/facts"
)

// serverConfigRules 数据库服务端配置审计（M8-3）。
// 配置事实来自各适配器的服务端模板（pg.hba/pg.settings/mssql.server_config/
// mysql.server_config/ora.profiles），与中间件配置审计同一模式。
var serverConfigRules = []struct {
	spec  RuleSpec
	check CheckFunc
}{
	// ---------- PostgreSQL: pg_hba ----------
	{
		spec: RuleSpec{
			ID: "db.pg.hba_trust", Version: "1",
			Name:        "PostgreSQL pg_hba 存在 trust 免密认证",
			Target:      facts.TargetDBPostgres,
			Description: "trust 方法不验证口令，任何能连到该规则范围的来源都可直接以对应角色登录。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskHigh,
			Remediation: "将 trust 改为 scram-sha-256（或证书认证），至少收紧来源地址范围。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "pg.hba" || f.Attributes["auth_method"] != "trust" {
					continue
				}
				if c.Baseline.Allowed(f.Subject, "hba", "trust", f.Attributes["address"]) {
					continue
				}
				hits = append(hits, CheckHit{
					Subject: f.Subject,
					Detail: fmt.Sprintf("pg_hba 第 %s 行 trust 免密（type=%s 地址=%s 库=%s）",
						f.Attributes["line_number"], f.Attributes["conn_type"],
						f.Attributes["address"], f.Attributes["databases"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "db.pg.hba_weak_method", Version: "1",
			Name:        "PostgreSQL pg_hba 使用弱认证方法",
			Target:      facts.TargetDBPostgres,
			Description: "网络连接使用 password（明文口令）或 ident（不可靠的外部身份断言）认证。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskMedium,
			Remediation: "改用 scram-sha-256 或证书认证；ident 仅限 local 且映射严格受控的场景。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "pg.hba" {
					continue
				}
				m := f.Attributes["auth_method"]
				if m != "password" && !(m == "ident" && strings.HasPrefix(f.Attributes["conn_type"], "host")) {
					continue
				}
				hits = append(hits, CheckHit{
					Subject: f.Subject,
					Detail: fmt.Sprintf("pg_hba 第 %s 行弱认证 %s（type=%s 地址=%s）",
						f.Attributes["line_number"], m, f.Attributes["conn_type"], f.Attributes["address"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "db.pg.hba_open_network", Version: "1",
			Name:        "PostgreSQL pg_hba 向全网段开放",
			Target:      facts.TargetDBPostgres,
			Description: "host 规则地址为 0.0.0.0/0 或 ::0/0 且非 reject：认证入口暴露于全部网络来源。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskMedium,
			Remediation: "把来源收紧到应用网段/跳板机；确需全网开放的记入基线并确保强认证。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "pg.hba" || !strings.HasPrefix(f.Attributes["conn_type"], "host") {
					continue
				}
				addr := f.Attributes["address"]
				mask := f.Attributes["netmask"]
				open := addr == "0.0.0.0/0" || addr == "::0/0" || addr == "::/0" ||
					(addr == "0.0.0.0" && (mask == "0" || mask == "0.0.0.0")) ||
					(addr == "::" && mask == "0") || addr == "all"
				if !open {
					continue
				}
				if f.Attributes["auth_method"] == "reject" {
					continue
				}
				if c.Baseline.Allowed(f.Subject, "hba", "open_network", addr) {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("pg_hba 第 %s 行对全网开放（认证=%s）", f.Attributes["line_number"], f.Attributes["auth_method"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "db.pg.password_encryption_weak", Version: "1",
			Name:        "PostgreSQL 口令加密为 md5",
			Target:      facts.TargetDBPostgres,
			Description: "password_encryption=md5 表示新设口令以 MD5 存储，弱于 scram-sha-256 且与 SCRAM 认证不兼容。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskMedium,
			Remediation: "改为 scram-sha-256 并轮换各角色口令使存储升级。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "pg.settings" || f.Attributes["name"] != "password_encryption" {
					continue
				}
				if !strings.EqualFold(f.Attributes["setting"], "md5") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  "server",
					Detail:   "password_encryption=md5（应为 scram-sha-256）",
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "db.pg.listen_all", Version: "1",
			Name:        "PostgreSQL 监听全部网卡",
			Target:      facts.TargetDBPostgres,
			Description: "listen_addresses 含 * 或 0.0.0.0：服务在所有网卡监听，实际暴露面由 pg_hba 与网络层共同决定。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskLow,
			Remediation: "收紧 listen_addresses 到业务网卡，或确认 pg_hba 与防火墙已收口并记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "pg.settings" || f.Attributes["name"] != "listen_addresses" {
					continue
				}
				v := f.Attributes["setting"]
				if !strings.Contains(v, "*") && !strings.Contains(v, "0.0.0.0") {
					continue
				}
				if c.Baseline.Allowed("server", "settings", "listen_all", "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  "server",
					Detail:   fmt.Sprintf("listen_addresses=%s（监听全部网卡）", v),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	// ---------- SQL Server: sys.configurations ----------
	{
		spec: RuleSpec{
			ID: "db.mssql.xp_cmdshell", Version: "1",
			Name:        "SQL Server xp_cmdshell 已启用",
			Target:      facts.TargetDBSQLSrv,
			Description: "xp_cmdshell 允许以服务账号身份执行操作系统命令，是数据库到主机的直接跳板。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskHigh,
			Remediation: "关闭 xp_cmdshell；确需使用的记入基线并限制调用主体。",
		},
		check: mssqlConfigCheck("xp_cmdshell", "xp_cmdshell 已启用（value_in_use=1）"),
	},
	{
		spec: RuleSpec{
			ID: "db.mssql.clr_enabled", Version: "1",
			Name:        "SQL Server CLR 集成已启用",
			Target:      facts.TargetDBSQLSrv,
			Description: "clr enabled 允许在数据库引擎内加载 .NET 程序集执行代码。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskMedium,
			Remediation: "无业务依赖时关闭 CLR 集成。",
		},
		check: mssqlConfigCheck("clr enabled", "clr enabled 已启用（value_in_use=1）"),
	},
	{
		spec: RuleSpec{
			ID: "db.mssql.cross_db_chaining", Version: "1",
			Name:        "SQL Server 跨库所有权链已启用",
			Target:      facts.TargetDBSQLSrv,
			Description: "cross db ownership chaining 打开时，低权库的所有权链可跨库放大权限。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskMedium,
			Remediation: "关闭服务器级跨库所有权链，按库单独评估。",
		},
		check: mssqlConfigCheck("cross db ownership chaining", "cross db ownership chaining 已启用（value_in_use=1）"),
	},
	{
		spec: RuleSpec{
			ID: "db.mssql.adhoc_distributed", Version: "1",
			Name:        "SQL Server 即席分布式查询已启用",
			Target:      facts.TargetDBSQLSrv,
			Description: "Ad Hoc Distributed Queries 允许 OPENROWSET/OPENDATASOURCE 访问外部数据源，可成为外联与横移通道。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskMedium,
			Remediation: "无业务依赖时关闭即席分布式查询。",
		},
		check: mssqlConfigCheck("Ad Hoc Distributed Queries", "Ad Hoc Distributed Queries 已启用（value_in_use=1）"),
	},
	// ---------- MySQL: global variables ----------
	{
		spec: RuleSpec{
			ID: "db.mysql.local_infile", Version: "1",
			Name:        "MySQL local_infile 已开启",
			Target:      facts.TargetDBMySQL,
			Description: "服务端 local_infile=ON 允许客户端 LOAD DATA LOCAL 读取服务端可达的客户端文件，配合恶意服务端/中间人可窃取文件。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskMedium,
			Remediation: "关闭 local_infile，除非 ETL 明确依赖且来源受控。",
		},
		check: mysqlVarCheck("local_infile", "ON", "local_infile=ON（允许 LOAD DATA LOCAL）"),
	},
	{
		spec: RuleSpec{
			ID: "db.mysql.general_log_on", Version: "1",
			Name:        "MySQL 通用查询日志开启",
			Target:      facts.TargetDBMySQL,
			Description: "general_log 记录全部语句（含可能出现的明文口令与业务数据），且持续写盘影响性能与磁盘。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskLow,
			Remediation: "生产环境关闭 general_log，排障窗口后及时关停。",
		},
		check: mysqlVarCheck("general_log", "ON", "general_log=ON（记录全部语句）"),
	},
	{
		spec: RuleSpec{
			ID: "db.mysql.name_resolve_on", Version: "1",
			Name:        "MySQL 未禁用名称解析",
			Target:      facts.TargetDBMySQL,
			Description: "skip_name_resolve=OFF 时基于主机名的授权依赖 DNS 解析结果，存在解析欺骗放大授权的风险。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskLow,
			Remediation: "启用 skip_name_resolve 并将授权改为 IP/网段形式。",
		},
		check: mysqlVarCheckInverse("skip_name_resolve", "OFF", "skip_name_resolve=OFF（主机名授权依赖 DNS 解析）"),
	},
	// ---------- Oracle: profiles ----------
	{
		spec: RuleSpec{
			ID: "db.oracle.profile_password_policy", Version: "1",
			Name:        "Oracle 概要文件口令策略无限制",
			Target:      facts.TargetDBOracle,
			Description: "概要文件的口令寿命/失败锁定/复用限制为 UNLIMITED 时，口令永不过期且无锁定保护。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskMedium,
			Remediation: "为各概要文件设置 PASSWORD_LIFE_TIME 与 FAILED_LOGIN_ATTEMPTS 等有限值，或记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			watched := map[string]bool{
				"PASSWORD_LIFE_TIME": true, "FAILED_LOGIN_ATTEMPTS": true,
				"PASSWORD_REUSE_MAX": true, "PASSWORD_REUSE_TIME": true,
				"PASSWORD_GRACE_TIME": true,
			}
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "ora.profiles" {
					continue
				}
				res := f.Attributes["resource"]
				if !watched[res] || !strings.EqualFold(f.Attributes["limit"], "UNLIMITED") {
					continue
				}
				if c.Baseline.Allowed(f.Subject, "profile", res, "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("概要文件 %s 的 %s = UNLIMITED", f.Subject, res),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
}

// mssqlConfigCheck 生成「配置项 value_in_use=1 即命中」的检查函数。
func mssqlConfigCheck(setting, detail string) CheckFunc {
	return func(c *EvalContext) []CheckHit {
		var hits []CheckHit
		for _, f := range c.ByKind[facts.FactAccountConfig] {
			if f.Source != "mssql.server_config" || f.Subject != setting {
				continue
			}
			if f.Attributes["value_in_use"] != "1" {
				continue
			}
			if c.Baseline.Allowed("server", "config", setting, "") {
				continue
			}
			hits = append(hits, CheckHit{
				Subject:  "server",
				Detail:   detail,
				Evidence: []string{f.FactID},
			})
		}
		return hits
	}
}

// mysqlVarCheck 变量等于期望危险值时命中。
func mysqlVarCheck(name, badValue, detail string) CheckFunc {
	return func(c *EvalContext) []CheckHit {
		var hits []CheckHit
		for _, f := range c.ByKind[facts.FactAccountConfig] {
			if f.Source != "mysql.server_config" || f.Attributes["name"] != name {
				continue
			}
			if !strings.EqualFold(f.Attributes["value"], badValue) {
				continue
			}
			if c.Baseline.Allowed("global", "variable", name, "") {
				continue
			}
			hits = append(hits, CheckHit{
				Subject:  "global",
				Detail:   detail,
				Evidence: []string{f.FactID},
			})
		}
		return hits
	}
}

// mysqlVarCheckInverse 与 mysqlVarCheck 相同语义（保留独立入口便于阅读：
// skip_name_resolve 的危险值就是 OFF）。
func mysqlVarCheckInverse(name, badValue, detail string) CheckFunc {
	return mysqlVarCheck(name, badValue, detail)
}
