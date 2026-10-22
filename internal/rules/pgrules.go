package rules

import (
	"fmt"
	"strings"

	"medaudit/internal/facts"
)

// postgresBuiltinRules PostgreSQL 目标内置规则（M4-2）。
var postgresBuiltinRules = []struct {
	spec  RuleSpec
	check CheckFunc
}{
	{
		spec: RuleSpec{
			ID: "db.pg.superuser", Version: "1",
			Name:        "PostgreSQL 角色拥有 SUPERUSER",
			Target:      facts.TargetDBPostgres,
			Description: "SUPERUSER 角色可绕过全部权限检查并执行任意系统操作。非内置初始化角色原则上不应持有。",
			Requires:    []facts.FactKind{facts.FactIdentity},
			Risk:        RiskHigh,
			Remediation: "回收 SUPERUSER，改为按需授予细粒度权限；确属业务必需的记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactIdentity] {
				if f.Source != "pg.roles" || f.Attributes["is_superuser"] != "true" {
					continue
				}
				if c.Baseline != nil && c.Baseline.Allowed(f.Subject, "role", "superuser", "") {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("角色 %s 拥有 SUPERUSER（可登录=%s）", f.Subject, f.Attributes["can_login"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "db.pg.dangerous_role_attrs", Version: "1",
			Name:        "PostgreSQL 非超级角色持有危险属性",
			Target:      facts.TargetDBPostgres,
			Description: "CREATEROLE / CREATEDB / REPLICATION / BYPASSRLS 均可用于权限提升或绕过行级安全，应逐个核实。",
			Requires:    []facts.FactKind{facts.FactIdentity},
			Risk:        RiskHigh,
			Remediation: "逐项核实危险属性的业务必需性，非必需即回收；必需的记入基线。",
		},
		check: func(c *EvalContext) []CheckHit {
			danger := []struct{ attr, label string }{
				{"can_create_role", "CREATEROLE"},
				{"can_create_db", "CREATEDB"},
				{"replication", "REPLICATION"},
				{"bypass_rls", "BYPASSRLS"},
			}
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactIdentity] {
				if f.Source != "pg.roles" || f.Attributes["is_superuser"] == "true" {
					continue // 超级用户由 db.pg.superuser 覆盖，避免重复命中
				}
				var got []string
				for _, d := range danger {
					if f.Attributes[d.attr] == "true" {
						got = append(got, d.label)
					}
				}
				if len(got) == 0 {
					continue
				}
				exempt := c.Baseline != nil
				for _, label := range got {
					if exempt && !c.Baseline.Allowed(f.Subject, "role_attr", label, "") {
						exempt = false
					}
				}
				if exempt {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("角色 %s 持有危险属性：%s", f.Subject, strings.Join(got, ", ")),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "db.pg.public_db_create", Version: "1",
			Name:        "PUBLIC 拥有数据库 CREATE 权限",
			Target:      facts.TargetDBPostgres,
			Description: "向 PUBLIC 授予数据库级 CREATE 等于允许任意角色在该库内建模式对象，违背最小权限。",
			Requires:    []facts.FactKind{facts.FactPrivilege},
			Risk:        RiskHigh,
			Remediation: "回收 PUBLIC 的数据库 CREATE，改为按角色显式授权。",
		},
		check: func(c *EvalContext) []CheckHit {
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactPrivilege] {
				if f.Source != "pg.db_privileges" || f.Subject != "PUBLIC" {
					continue
				}
				if f.Attributes["privilege"] != "CREATE" {
					continue
				}
				hits = append(hits, CheckHit{
					Subject:  f.Subject,
					Detail:   fmt.Sprintf("PUBLIC 在数据库 %s 拥有 CREATE", f.Attributes["database"]),
					Evidence: []string{f.FactID},
				})
			}
			return hits
		},
	},
	{
		spec: RuleSpec{
			ID: "db.pg.public_writable", Version: "1",
			Name:        "PUBLIC 拥有可写对象/模式权限",
			Target:      facts.TargetDBPostgres,
			Description: "PUBLIC 对表拥有 INSERT/UPDATE/DELETE/TRUNCATE 或对模式拥有 CREATE，等同任意连接用户可写。",
			Requires:    []facts.FactKind{facts.FactPrivilege},
			Risk:        RiskHigh,
			Remediation: "回收 PUBLIC 的写权限，改为按应用角色显式授权。",
		},
		check: func(c *EvalContext) []CheckHit {
			writePrivs := map[string]bool{"INSERT": true, "UPDATE": true, "DELETE": true, "TRUNCATE": true}
			var hits []CheckHit
			for _, f := range c.ByKind[facts.FactPrivilege] {
				if f.Subject != "PUBLIC" {
					continue
				}
				switch f.Source {
				case "pg.object_privileges":
					if writePrivs[f.Attributes["privilege"]] {
						hits = append(hits, CheckHit{
							Subject: f.Subject,
							Detail: fmt.Sprintf("PUBLIC 对 %s.%s（%s）拥有 %s",
								f.Attributes["schema"], f.Attributes["object"],
								f.Attributes["database"], f.Attributes["privilege"]),
							Evidence: []string{f.FactID},
						})
					}
				case "pg.schema_privileges":
					if f.Attributes["privilege"] == "CREATE" {
						hits = append(hits, CheckHit{
							Subject: f.Subject,
							Detail: fmt.Sprintf("PUBLIC 在模式 %s（%s）拥有 CREATE",
								f.Attributes["schema"], f.Attributes["database"]),
							Evidence: []string{f.FactID},
						})
					}
				}
			}
			return hits
		},
	},
}
