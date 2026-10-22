package sqlserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"medaudit/internal/collect/db/dbutil"
	"medaudit/internal/facts"
)

const (
	collectVersion = "0.2.0-m1"
	maxDatabases   = 20 // 按库采集的数据库数量上限
)

// Collect 运行全部 SQL Server 模板：服务器层 + 按库数据库层，输出带收据的事实包。
// DENY 语义保留；固定角色权限须与 server_role_members 联合判断（规则引擎侧）。
func Collect(ctx context.Context, cfg Config) (*facts.FactBundle, error) {
	db, err := Connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	now := time.Now().UTC().Truncate(time.Second)
	b := &facts.FactBundle{
		SchemaVersion: facts.SchemaVersion,
		BundleID:      "bundle-mssql-" + now.Format("20060102-150405"),
		PlanID:        "plan-m1",
		Collector: facts.CollectorInfo{
			Name:           "medaudit-collector",
			Version:        collectVersion,
			Adapter:        facts.TargetDBSQLSrv,
			AdapterVersion: collectVersion,
		},
		CollectedAt: facts.TimeRange{Started: now},
		Scope: facts.Scope{
			HospitalID: "h-m1",
			AssetID:    fmt.Sprintf("mssql-%s:%d", cfg.Host, cfg.Port),
			TargetType: facts.TargetDBSQLSrv,
			Profile:    "m1-full",
		},
		Identities: facts.Identities{
			CollectorIdentity: cfg.User + "@collector",
			TargetIdentity:    "multiple@principals",
			AppIdentitySource: "unknown",
		},
	}

	templates, err := LoadTemplates()
	if err != nil {
		return nil, err
	}
	byID := map[string]Template{}
	for _, t := range templates {
		byID[t.ID] = t
	}

	seq := 0
	nextID := func() string { seq++; return fmt.Sprintf("mssql-fact-%06d", seq) }
	failed := false

	run := func(t Template, query, paramDigest string, mapFn func(*dbutil.Rows)) error {
		start := time.Now()
		r, qerr := dbutil.QueryRows(ctx, db, query, 0, 0, 0)
		end := time.Now()
		rc := facts.Receipt{
			TemplateID:      t.ID,
			TemplateVersion: t.Version,
			Started:         start.UTC().Truncate(time.Second),
			Finished:        end.UTC().Truncate(time.Second),
			DurationMs:      end.Sub(start).Milliseconds(),
			Status:          "ok",
			Visibility:      "full",
		}
		if paramDigest != "" {
			rc.ParamDigest = paramDigest
		}
		switch {
		case qerr != nil && dbutil.IsPermissionDenied(qerr):
			rc.Status = "denied"
			rc.ErrorStage = "query"
			b.Receipts = append(b.Receipts, rc)
			b.Facts = append(b.Facts, facts.Fact{
				FactID: nextID(), Kind: facts.FactIdentity, Subject: t.ID,
				Status: facts.StatusPermissionDenied, Source: t.ID,
			})
			return nil
		case qerr != nil:
			rc.Status = "failed"
			rc.ErrorStage = "query"
			failed = true
			b.Receipts = append(b.Receipts, rc)
			return fmt.Errorf("template %s: %w", t.ID, qerr)
		default:
			rc.RowCount = len(r.Data)
			if r.Truncated {
				rc.Truncated = true
				rc.Status = "partial"
			}
			b.Receipts = append(b.Receipts, rc)
			mapFn(r)
			return nil
		}
	}

	rowMap := func(r *dbutil.Rows, i int) map[string]string {
		m := map[string]string{}
		for j, c := range r.Columns {
			m[strings.ToLower(c)] = r.Data[i][j]
		}
		return m
	}

	// 服务器层模板。
	for _, tid := range []string{"mssql.server_principals", "mssql.server_role_members", "mssql.server_permissions", "mssql.server_config"} {
		t := byID[tid]
		mapFn := mapServerTemplate(tid, b, nextID, rowMap)
		if err := run(t, t.SQL, "", mapFn); err != nil {
			return finish(b, failed, err)
		}
	}

	// 数据库清单。
	var databases []string
	if t, ok := byID["mssql.databases"]; ok {
		mapFn := func(r *dbutil.Rows) {
			for i := range r.Data {
				m := rowMap(r, i)
				if m["database_name"] != "" {
					databases = append(databases, m["database_name"])
				}
			}
		}
		if err := run(t, t.SQL, "", mapFn); err != nil {
			return finish(b, failed, err)
		}
	}
	if len(databases) > maxDatabases {
		databases = databases[:maxDatabases]
		// 在 databases 收据上标记截断。
		for i := len(b.Receipts) - 1; i >= 0; i-- {
			if b.Receipts[i].TemplateID == "mssql.databases" {
				b.Receipts[i].Truncated = true
				b.Receipts[i].Status = "partial"
				break
			}
		}
	}

	// 按库模板。
	for _, dbName := range databases {
		for _, tid := range []string{"mssql.db_principals", "mssql.db_role_members", "mssql.db_permissions"} {
			t := byID[tid]
			q, err := t.Instantiate(map[string]string{"DB": dbName})
			if err != nil {
				return finish(b, true, err)
			}
			mapFn := mapDBTemplate(tid, dbName, b, nextID, rowMap)
			if err := run(t, q, "db="+dbName, mapFn); err != nil {
				return finish(b, failed, err)
			}
		}
	}

	// 记录本次实际连接身份（与被核查主体分开）。
	b.Facts = append(b.Facts, facts.Fact{
		FactID:     nextID(),
		Kind:       facts.FactIdentity,
		Subject:    cfg.User + "@collector-session",
		Status:     facts.StatusObserved,
		Source:     "mssql.session",
		Attributes: map[string]string{"note": "collector connection identity, not application identity"},
	})

	return finish(b, failed, nil)
}

func finish(b *facts.FactBundle, failed bool, err error) (*facts.FactBundle, error) {
	switch {
	case err != nil:
		b.Execution = facts.ExecutionFailed
	case failed:
		b.Execution = facts.ExecutionFailed
	default:
		b.Execution = facts.ExecutionComplete
	}
	// partial 由调用方在 run 闭包中设置；此处根据收据复核。
	for _, rc := range b.Receipts {
		if rc.Status == "partial" || rc.Status == "denied" {
			if b.Execution == facts.ExecutionComplete {
				b.Execution = facts.ExecutionPartial
			}
			break
		}
	}
	b.CollectedAt.Finished = time.Now().UTC().Truncate(time.Second)
	if verrs := b.Validate(); len(verrs) != 0 {
		return b, fmt.Errorf("bundle validate: %v", verrs)
	}
	return b, err
}

func mapServerTemplate(tid string, b *facts.FactBundle, nextID func() string,
	rowMap func(*dbutil.Rows, int) map[string]string) func(*dbutil.Rows) {

	return func(r *dbutil.Rows) {
		for i := range r.Data {
			m := rowMap(r, i)
			switch tid {
			case "mssql.server_principals":
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactIdentity,
					Subject: m["principal_name"],
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: map[string]string{
						"principal_type": m["principal_type"], "is_disabled": m["is_disabled"],
						"default_database_name": m["default_database_name"],
					},
				})
			case "mssql.server_role_members":
				b.Facts = append(b.Facts, facts.Fact{
					FactID:         nextID(),
					Kind:           facts.FactRoleEdge,
					Subject:        m["member_name"],
					Status:         facts.StatusObserved,
					Source:         tid,
					PermissionPath: []string{m["role_name"], m["member_name"]},
					Activation:     facts.ActivationDefault,
					Attributes:     map[string]string{"member_type": m["member_type"]},
				})
			case "mssql.server_config":
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactAccountConfig,
					Subject: m["setting_name"],
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: map[string]string{
						"value_in_use": m["value_in_use"], "is_dynamic": m["is_dynamic"],
					},
				})
			case "mssql.server_permissions":
				g := m["state_desc"] == "GRANT_WITH_GRANT_OPTION"
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactPrivilege,
					Subject: m["grantee_name"],
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: map[string]string{
						"permission": m["permission_name"], "state": m["state_desc"],
						"class": m["class_desc"], "grantee_type": m["grantee_type"],
					},
					Scope:     "server",
					Grantable: &g,
				})
			}
		}
	}
}

func mapDBTemplate(tid, dbName string, b *facts.FactBundle, nextID func() string,
	rowMap func(*dbutil.Rows, int) map[string]string) func(*dbutil.Rows) {

	return func(r *dbutil.Rows) {
		for i := range r.Data {
			m := rowMap(r, i)
			attrs := func(extra map[string]string) map[string]string {
				a := map[string]string{"database": dbName}
				for k, v := range extra {
					a[k] = v
				}
				return a
			}
			switch tid {
			case "mssql.db_principals":
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactIdentity,
					Subject: m["principal_name"],
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: attrs(map[string]string{
						"principal_type": m["principal_type"], "authentication_type": m["authentication_type"],
					}),
				})
			case "mssql.db_role_members":
				b.Facts = append(b.Facts, facts.Fact{
					FactID:         nextID(),
					Kind:           facts.FactRoleEdge,
					Subject:        m["member_name"],
					Status:         facts.StatusObserved,
					Source:         tid,
					PermissionPath: []string{m["role_name"], m["member_name"]},
					Activation:     facts.ActivationDefault,
					Attributes:     attrs(map[string]string{"member_type": m["member_type"]}),
				})
			case "mssql.db_permissions":
				g := m["state_desc"] == "GRANT_WITH_GRANT_OPTION"
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactPrivilege,
					Subject: m["grantee_name"],
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: attrs(map[string]string{
						"permission": m["permission_name"], "state": m["state_desc"],
						"class": m["class_desc"], "grantee_type": m["grantee_type"],
					}),
					Scope:     "database:" + dbName,
					Grantable: &g,
				})
			}
		}
	}
}
