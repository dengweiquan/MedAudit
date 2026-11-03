package rules

import (
	"fmt"
	"strconv"
	"strings"

	"medaudit/internal/facts"
)

// serverConfigRules 数据库服务端配置审计（M8-3）。
// 配置事实来自各适配器的服务端模板（pg.hba/pg.settings/mssql.server_config/
// mysql.server_config/ora.profiles），与中间件配置审计同一模式。

// pgAuditEvidence pg.settings 审计规则的证据门控：
//   - 收据被拒/失败/无收据 → Missing；
//   - 收据截断：仅当已见审计事件开关（log_connections=on 或 log_statement 非 none）时 Ready（PASS 可靠）；
//     否则 Missing——“无审计事件”是完整清单判断，不能在截断结果上推断；
//   - 收据成功：见任一审计相关事实 → Ready（模板固定查三开关，收据成功即查询完整）。
func pgAuditEvidence(c *EvalContext) (EvidenceStatus, string) {
	var saw, partial bool
	for _, rc := range c.Bundle.Receipts {
		if rc.TemplateID != "pg.settings" {
			continue
		}
		saw = true
		switch rc.Status {
		case "denied", "failed":
			reason := rc.ErrorStage
			if reason == "" {
				reason = rc.Status
			}
			return EvidenceMissing, fmt.Sprintf("pg.settings 采集失败：%s，无法判定", reason)
		case "partial":
			partial = true
		}
		if rc.Truncated {
			partial = true
		}
	}
	if !saw {
		return EvidenceMissing, "未采集到 pg.settings 证据（旧包或未执行），无法判定"
	}
	vals := map[string]string{}
	for _, f := range c.Bundle.Facts {
		if f.Source != "pg.settings" || f.Status != facts.StatusObserved {
			continue
		}
		switch f.Attributes["name"] {
		case "logging_collector", "log_connections", "log_statement":
			vals[f.Attributes["name"]] = strings.ToLower(f.Attributes["setting"])
		}
	}
	event := vals["log_connections"] == "on" ||
		(vals["log_statement"] != "" && vals["log_statement"] != "none")
	if partial {
		if event {
			return EvidenceReady, ""
		}
		return EvidenceMissing, "pg.settings 证据被截断，无法确认审计事件开关"
	}
	if len(vals) > 0 {
		return EvidenceReady, ""
	}
	return EvidenceMissing, "pg.settings 查询成功但无审计相关事实，无法判定"
}

// mysqlPasswordEvidence validate_password 规则的证据门控。
// 两项各有量纲（策略 ∈ LOW/MEDIUM/STRONG/0/1/2，长度为非负整数）；
// 门控只放行两种情形：(a) 已有确定的违规（策略 LOW/0，或长度合法且 <8）
// ——违规不依赖另一项，check 命中即 FAIL；(b) 两项同时合法——check 可完整判定。
// 其余（任一缺失/非法且无确定违规）→ Missing（UNKNOWN），不得误判 PASS：
// 如只有 policy=MEDIUM 而 length 未采集，长度 <8 的弱口令会被漏判为通过。
func mysqlPasswordEvidence(c *EvalContext) (EvidenceStatus, string) {
	if st, reason := receiptVerdict(c, "mysql.server_config"); st != EvidenceReady {
		return st, reason
	}
	var policy, length string
	policyOK, lengthOK, definiteFail := false, false, false
	for _, f := range c.Bundle.Facts {
		if f.Source != "mysql.server_config" || f.Status != facts.StatusObserved {
			continue
		}
		switch f.Attributes["name"] {
		case "validate_password.policy":
			policy = f.Attributes["value"]
			switch strings.ToUpper(strings.TrimSpace(policy)) {
			case "LOW", "0":
				policyOK, definiteFail = true, true
			case "MEDIUM", "STRONG", "1", "2":
				policyOK = true
			}
		case "validate_password.length":
			length = f.Attributes["value"]
			if n, err := strconv.Atoi(strings.TrimSpace(length)); err == nil && n >= 0 {
				lengthOK = true
				if n < 8 {
					definiteFail = true
				}
			}
		}
	}
	if definiteFail || (policyOK && lengthOK) {
		return EvidenceReady, ""
	}
	return EvidenceMissing, fmt.Sprintf(
		"mysql.server_config 的 validate_password.policy（%q）与 length（%q）须同时合法（或已有确定违规），当前无法判定",
		policy, length)
}

// mssqlAuditEvidence sys.server_audits 规则的证据门控（不沿用通用 Partial 语义：
// 通用 Partial 会跑 check，而零行 FAIL 是完整清单判断，不能在截断结果上推断）。
//   - 收据被拒/失败/无收据 → Missing（UNKNOWN）；冲突收据（ok 与 denied/failed 并存）同样 Missing；
//   - 任一收据截断（partial）：仅当已见启用审计时 Ready（PASS 可靠）；否则 Missing；
//   - 收据全成功：见启用审计 → Ready；见审计但均未启用 → Ready（完整清单，FAIL 可靠）；
//     零行 → 仅当同包可见性自查为 sufficient 时 Ready（否则 Missing：目录视图按可见性过滤，
//     零行不能认定未配置审计；旧包无自查事实时同样 Missing）。
func mssqlAuditEvidence(c *EvalContext) (EvidenceStatus, string) {
	var saw, partial bool
	for _, rc := range c.Bundle.Receipts {
		if rc.TemplateID != "mssql.server_audits" {
			continue
		}
		saw = true
		switch rc.Status {
		case "denied", "failed":
			reason := rc.ErrorStage
			if reason == "" {
				reason = rc.Status
			}
			return EvidenceMissing, fmt.Sprintf("mssql.server_audits 采集失败：%s，无法判定", reason)
		case "partial":
			partial = true
		}
		if rc.Truncated {
			partial = true
		}
	}
	if !saw {
		return EvidenceMissing, "未采集到 mssql.server_audits 证据（旧包或未执行），无法判定"
	}
	var anyFact, anyEnabled bool
	for _, f := range c.Bundle.Facts {
		if f.Source != "mssql.server_audits" || f.Status != facts.StatusObserved {
			continue
		}
		anyFact = true
		if v := strings.ToLower(f.Attributes["is_state_enabled"]); v == "1" || v == "true" {
			anyEnabled = true
		}
	}
	if partial {
		if anyEnabled {
			return EvidenceReady, ""
		}
		return EvidenceMissing, "mssql.server_audits 证据被截断，无法确认是否存在启用审计"
	}
	if anyEnabled || anyFact {
		return EvidenceReady, ""
	}
	for _, f := range c.Bundle.Facts {
		if f.Source == "mssql.audit_visibility" && f.Status == facts.StatusObserved &&
			f.Attributes["visibility"] == "sufficient" {
			return EvidenceReady, ""
		}
	}
	return EvidenceMissing, "sys.server_audits 查询成功但零行，且采集账号元数据可见性不足（非 sysadmin/CONTROL SERVER），无法认定未配置审计"
}

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
	{
		spec: RuleSpec{
			ID: "db.pg.ssl_off", Version: "3",
			Name:        "PostgreSQL 未启用 SSL",
			Target:      facts.TargetDBPostgres,
			Description: "ssl=off 时数据库连接不加密，口令与业务数据在网络上传输可被窃听。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Evidence:    EvidenceSourceValue("pg.settings", "name", []string{"ssl"}, "setting", pgBoolValue, false),
			Risk:        RiskMedium,
			Remediation: "启用 ssl 并配置有效证书；客户端以 hostssl 限定加密连接。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "pg.settings" || f.Attributes["name"] != "ssl" {
					continue
				}
				if !strings.EqualFold(f.Attributes["setting"], "off") {
					continue
				}
				if c.Baseline.Allowed("server", "settings", "ssl_off", "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  "server",
					Detail:   "ssl=off（数据库连接未加密）",
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "db.pg.audit_off", Version: "3",
			Name:        "PostgreSQL 未启用审计日志",
			Target:      facts.TargetDBPostgres,
			Description: "log_connections 与 log_statement 均未表明审计事件开启时，数据库无审计轨迹。注意：logging_collector=on 仅启用收集进程，不产生审计事件，不能单独作为审计已开启的证据；事件经 stderr/syslog 等其他输出路径时仍算审计，只评价实采的三个开关；pgaudit 等扩展审计不在本规则评价范围。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Evidence:    pgAuditEvidence,
			Risk:        RiskMedium,
			Remediation: "打开 log_connections（至少记录连接审计），或将 log_statement 设为 ddl 或 mod；logging_collector 仅决定日志收集方式，不产生审计事件。",
		},
		check: func(c *EvalContext) []CheckHit {
			vals := map[string]string{}
			var ev []string
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "pg.settings" || f.Status != facts.StatusObserved {
					continue
				}
				switch f.Attributes["name"] {
				case "logging_collector", "log_connections", "log_statement":
					vals[f.Attributes["name"]] = strings.ToLower(f.Attributes["setting"])
					ev = append(ev, f.FactID)
				}
			}
			// 只有事件开关（log_connections / log_statement）能证明审计事件开启；
			// logging_collector 单独为 on 不算（它只启用收集进程）。
			if vals["log_connections"] == "on" {
				return nil
			}
			if s := vals["log_statement"]; s != "" && s != "none" {
				return nil
			}
			if c.Baseline.Allowed("server", "settings", "audit_off", "") {
				return nil
			}
			return []CheckHit{{
				Subject:  "server",
				Detail:   fmt.Sprintf("未启用审计事件（log_connections=%s，log_statement=%s；logging_collector=%s 仅启用收集器，不产生审计事件）", vals["log_connections"], vals["log_statement"], vals["logging_collector"]),
				Evidence: ev,
			}}
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
	{
		spec: RuleSpec{
			ID: "db.mssql.password_policy", Version: "2",
			Name:        "SQL Server 登录口令策略未启用",
			Target:      facts.TargetDBSQLSrv,
			Description: "SQL 登录的 CHECK_POLICY 或 CHECK_EXPIRATION 为 OFF 时，口令不受 Windows 口令策略约束或永不过期。",
			Requires:    []facts.FactKind{facts.FactIdentity},
			// 证据门控：旧包的主体事实无 is_policy_checked 属性时为 UNKNOWN；
			// 实例确实无 SQL 登录时为空集，check 判 PASS（空集语义）。
			Evidence: func(c *EvalContext) (EvidenceStatus, string) {
				if st, reason := receiptVerdict(c, "mssql.server_principals"); st != EvidenceReady {
					return st, reason
				}
				var sawLogin, sawAttr bool
				for _, f := range c.Bundle.Facts {
					if f.Source != "mssql.server_principals" || f.Status != facts.StatusObserved {
						continue
					}
					if f.Attributes["principal_type"] != "SQL_LOGIN" {
						continue
					}
					sawLogin = true
					if _, ok := f.Attributes["is_policy_checked"]; ok {
						sawAttr = true
					}
				}
				if sawLogin && !sawAttr {
					return EvidenceMissing, "mssql.server_principals 查询成功但 SQL_LOGIN 事实无 is_policy_checked 属性（旧包），无法判定"
				}
				return EvidenceReady, ""
			},
			Risk:        RiskMedium,
			Remediation: "对 SQL 登录启用 CHECK_POLICY 与 CHECK_EXPIRATION；服务账号确需豁免的记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactIdentity] {
				if f.Source != "mssql.server_principals" || f.Attributes["principal_type"] != "SQL_LOGIN" {
					continue
				}
				if v := strings.ToLower(f.Attributes["is_disabled"]); v == "1" || v == "true" {
					continue
				}
				if v := strings.ToLower(f.Attributes["is_policy_checked"]); v == "0" || v == "false" {
					if !c.Baseline.Allowed(f.Subject, "login", "check_policy", "") {
						hits = append(hits, CheckHit{
							Subject:  f.Subject,
							Detail:   fmt.Sprintf("登录 %s 的 CHECK_POLICY=OFF（口令不受策略约束）", f.Subject),
							Evidence: []string{f.FactID},
						})
					}
				}
				if v := strings.ToLower(f.Attributes["is_expiration_checked"]); v == "0" || v == "false" {
					if !c.Baseline.Allowed(f.Subject, "login", "check_expiration", "") {
						hits = append(hits, CheckHit{
							Subject:  f.Subject,
							Detail:   fmt.Sprintf("登录 %s 的 CHECK_EXPIRATION=OFF（口令永不过期）", f.Subject),
							Evidence: []string{f.FactID},
						})
					}
				}
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "db.mssql.audit_off", Version: "3",
			Name:        "SQL Server 未启用服务器审计",
			Target:      facts.TargetDBSQLSrv,
			Description: "sys.server_audits 中无启用状态的服务器审计时，数据库操作无审计轨迹。零行只有在采集账号可见性充分（sysadmin 或 CONTROL SERVER，同包 mssql.audit_visibility 自查）时才认定未配置审计；可见性不足、截断或旧包无自查时零行判 UNKNOWN，不自动提权。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Evidence:    mssqlAuditEvidence,
			Risk:        RiskMedium,
			Remediation: "创建并启用服务器审计（及数据库审计规范），审计目标指向受保护的存储。",
		},
		check: func(c *EvalContext) []CheckHit {
			enabled := false
			var ev []string
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "mssql.server_audits" || f.Status != facts.StatusObserved {
					continue
				}
				ev = append(ev, f.FactID)
				if v := strings.ToLower(f.Attributes["is_state_enabled"]); v == "1" || v == "true" {
					enabled = true
				}
			}
			if enabled {
				return nil
			}
			if c.Baseline.Allowed("server", "audit", "server_audits", "") {
				return nil
			}
			detail := "未启用服务器审计（sys.server_audits 中无启用项）"
			if len(ev) == 0 {
				// 证据门控已保证可见性充分：零行即“未配置任何审计”，不是“未采集”或“不可见”。
				detail = "未启用服务器审计（sys.server_audits 查询成功且零行，采集账号可见性充分，认定未配置任何审计）"
			}
			return []CheckHit{{
				Subject:  "server",
				Detail:   detail,
				Evidence: ev,
			}}
		},
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
			Description: "general_log 记录全部语句，语句文本可能含明文口令与业务数据，存在敏感信息明文落盘风险（是否实际含患者明文须结合日志内容判定，本规则不断言）；且持续写盘影响性能与磁盘。",
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
	{
		spec: RuleSpec{
			ID: "db.mysql.password_policy", Version: "3",
			Name:        "MySQL 口令策略弱",
			Target:      facts.TargetDBMySQL,
			Description: "validate_password 策略为 LOW 或长度要求低于 8 位时，弱口令可直接通过；未采集到该变量时结论为证据不足（UNKNOWN），不判通过。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Evidence:    mysqlPasswordEvidence,
			Risk:        RiskMedium,
			Remediation: "安装并启用 validate_password 组件，策略设为 MEDIUM 及以上、长度至少 8 位。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "mysql.server_config" {
					continue
				}
				switch f.Attributes["name"] {
				case "validate_password.policy":
					if v := strings.ToUpper(f.Attributes["value"]); v == "LOW" || v == "0" {
						if !c.Baseline.Allowed("global", "variable", "validate_password.policy", "") {
							hits = append(hits, CheckHit{
								Subject:  "global",
								Detail:   fmt.Sprintf("validate_password.policy=%s（复杂度过低）", f.Attributes["value"]),
								Evidence: []string{f.FactID},
							})
						}
					}
				case "validate_password.length":
					n, err := strconv.Atoi(strings.TrimSpace(f.Attributes["value"]))
					if err == nil && n < 8 {
						if !c.Baseline.Allowed("global", "variable", "validate_password.length", "") {
							hits = append(hits, CheckHit{
								Subject:  "global",
								Detail:   fmt.Sprintf("validate_password.length=%d（低于 8 位）", n),
								Evidence: []string{f.FactID},
							})
						}
					}
				}
			}
			return hits
		},
	},
	// ---------- Oracle: profiles ----------
	{
		spec: RuleSpec{
			ID: "db.oracle.profile_password_policy", Version: "2",
			Name:        "Oracle 概要文件口令策略无限制",
			Target:      facts.TargetDBOracle,
			Description: "概要文件的口令寿命/失败锁定/复用限制为 UNLIMITED，或未设置口令复杂度验证函数时，口令永不过期、无锁定保护或无复杂度约束。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Risk:        RiskMedium,
			Remediation: "为各概要文件设置 PASSWORD_LIFE_TIME 与 FAILED_LOGIN_ATTEMPTS 等有限值并配置 PASSWORD_VERIFY_FUNCTION，或记入基线。",
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
				if res == "PASSWORD_VERIFY_FUNCTION" {
					if strings.TrimSpace(f.Attributes["limit"]) == "" {
						if c.Baseline.Allowed(f.Subject, "profile", res, "") {
							continue
						}
						hits = append(hits, CheckHit{
							Subject:  f.Subject,
							Detail:   fmt.Sprintf("概要文件 %s 未设置口令复杂度验证函数", f.Subject),
							Evidence: []string{f.FactID},
						})
					}
					continue
				}
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
	{
		spec: RuleSpec{
			ID: "db.oracle.audit_trail_off", Version: "4",
			Name:        "Oracle 传统审计未启用",
			Target:      facts.TargetDBOracle,
			Description: "AUDIT_TRAIL=NONE 时传统审计关闭，传统审计轨迹缺失。本规则只评价传统审计，不评价统一审计（Unified Auditing）：12c+ 环境即使 AUDIT_TRAIL=NONE 也可能已启用统一审计，需另查统一审计模式与策略；统一审计不在本规则评价范围，本规则结论不等于“数据库完全无审计”。",
			Requires:    []facts.FactKind{facts.FactAccountConfig},
			Evidence:    EvidenceSourceValue("ora.parameters", "name", []string{"AUDIT_TRAIL"}, "value", auditTrailValue, false),
			Risk:        RiskMedium,
			Remediation: "将 AUDIT_TRAIL 设为 DB（或 DB_EXTENDED）并重启生效；或确认统一审计已启用并覆盖所需策略，审计记录定期归档。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactAccountConfig] {
				if f.Source != "ora.parameters" || f.Attributes["name"] != "AUDIT_TRAIL" {
					continue
				}
				if !strings.EqualFold(f.Attributes["value"], "NONE") {
					continue
				}
				if c.Baseline.Allowed("server", "parameter", "audit_trail", "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  "server",
					Detail:   "AUDIT_TRAIL=NONE（传统审计未启用；统一审计不在本规则评价范围）",
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
