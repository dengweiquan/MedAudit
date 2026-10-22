// PostgreSQL 采集：运行全部模板（集群范围 + 当前连接库的对象层），输出带收据的事实包。
// 对象级模板只覆盖配置中的连接库（scope 属性标明 database），多库需多次采集：
// 这是 PG 目录结构使然，不以“不支持”为由静默缺席——覆盖边界如实记录。
package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"medaudit/internal/collect/db/dbutil"
	"medaudit/internal/facts"
)

const collectVersion = "0.3.0-m4"

// Collect 运行全部 PostgreSQL 模板，输出带收据的事实包。
func Collect(ctx context.Context, cfg Config) (*facts.FactBundle, error) {
	db, err := Connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	now := time.Now().UTC().Truncate(time.Second)
	b := &facts.FactBundle{
		SchemaVersion: facts.SchemaVersion,
		BundleID:      "bundle-pg-" + now.Format("20060102-150405"),
		PlanID:        "plan-m4",
		Collector: facts.CollectorInfo{
			Name:           "medaudit-collector",
			Version:        collectVersion,
			Adapter:        facts.TargetDBPostgres,
			AdapterVersion: collectVersion,
		},
		CollectedAt: facts.TimeRange{Started: now},
		Scope: facts.Scope{
			HospitalID: "h-m4",
			AssetID:    fmt.Sprintf("pg-%s:%d", cfg.Host, cfg.Port),
			TargetType: facts.TargetDBPostgres,
			Profile:    "m4-full",
		},
		Identities: facts.Identities{
			CollectorIdentity: cfg.User + "@collector",
			TargetIdentity:    "multiple@roles",
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
	nextID := func() string { seq++; return fmt.Sprintf("pg-fact-%06d", seq) }
	failed := false
	connectedDB := ""

	run := func(t Template, mapFn func(*dbutil.Rows)) error {
		start := time.Now()
		r, qerr := dbutil.QueryRows(ctx, db, t.SQL, 0, 0, 0)
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

	order := []string{
		"pg.instance", "pg.roles", "pg.role_members", "pg.databases",
		"pg.db_privileges", "pg.schema_privileges", "pg.object_privileges", "pg.role_settings",
		"pg.hba", "pg.settings",
	}
	for _, tid := range order {
		t, ok := byID[tid]
		if !ok {
			return finish(b, true, fmt.Errorf("template %s 缺失", tid))
		}
		mapFn := mapTemplate(tid, b, nextID, rowMap, &connectedDB)
		if err := run(t, mapFn); err != nil {
			return finish(b, failed, err)
		}
	}

	// 记录本次实际连接身份（与被核查主体分开）。
	b.Facts = append(b.Facts, facts.Fact{
		FactID:     nextID(),
		Kind:       facts.FactIdentity,
		Subject:    cfg.User + "@collector-session",
		Status:     facts.StatusObserved,
		Source:     "pg.session",
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

func boolp(s string) *bool {
	v := s == "true" || s == "t" || s == "1"
	return &v
}

func mapTemplate(tid string, b *facts.FactBundle, nextID func() string,
	rowMap func(*dbutil.Rows, int) map[string]string, connectedDB *string) func(*dbutil.Rows) {

	return func(r *dbutil.Rows) {
		for i := range r.Data {
			m := rowMap(r, i)
			switch tid {
			case "pg.instance":
				*connectedDB = m["database_name"]
				b.Scope.TargetVersion = m["server_version"]
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactIdentity,
					Subject: m["database_name"],
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: map[string]string{
						"server_version": m["server_version"], "current_user": m["current_user_name"],
						"session_user": m["session_user_name"], "server_port": m["server_port"],
					},
				})
			case "pg.roles":
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactIdentity,
					Subject: m["role_name"],
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: map[string]string{
						"is_superuser": m["is_superuser"], "inherit": m["inherit"],
						"can_create_role": m["can_create_role"], "can_create_db": m["can_create_db"],
						"can_login": m["can_login"], "replication": m["replication"],
						"bypass_rls": m["bypass_rls"], "valid_until": m["valid_until"],
						"conn_limit": m["conn_limit"],
					},
				})
			case "pg.role_members":
				b.Facts = append(b.Facts, facts.Fact{
					FactID:         nextID(),
					Kind:           facts.FactRoleEdge,
					Subject:        m["member_name"],
					Status:         facts.StatusObserved,
					Source:         tid,
					PermissionPath: []string{m["role_name"], m["member_name"]},
					Activation:     facts.ActivationDefault,
					Grantable:      boolp(m["admin_option"]),
					Attributes:     map[string]string{"grantor": m["grantor_name"], "admin_option": m["admin_option"]},
				})
			case "pg.databases":
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactIdentity,
					Subject: m["database_name"],
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: map[string]string{
						"owner": m["owner_name"], "encoding": m["encoding"],
						"allow_conn": m["allow_conn"], "is_template": m["is_template"],
					},
				})
			case "pg.db_privileges":
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactPrivilege,
					Subject: m["grantee_name"],
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: map[string]string{
						"privilege": m["privilege_type"], "database": m["database_name"],
					},
					Scope:     "database:" + m["database_name"],
					Grantable: boolp(m["is_grantable"]),
				})
			case "pg.schema_privileges":
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactPrivilege,
					Subject: m["grantee_name"],
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: map[string]string{
						"privilege": m["privilege_type"], "schema": m["schema_name"],
						"database": *connectedDB,
					},
					Scope:     "database:" + *connectedDB + "/schema:" + m["schema_name"],
					Grantable: boolp(m["is_grantable"]),
				})
			case "pg.object_privileges":
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactPrivilege,
					Subject: m["grantee_name"],
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: map[string]string{
						"privilege": m["privilege_type"], "object": m["object_name"],
						"object_kind": m["object_kind"], "schema": m["schema_name"],
						"database": *connectedDB,
					},
					Scope:     "database:" + *connectedDB + "/schema:" + m["schema_name"],
					Grantable: boolp(m["is_grantable"]),
				})
			case "pg.hba":
				subj := m["user_names"]
				if subj == "" {
					subj = "all"
				}
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactAccountConfig,
					Subject: subj,
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: map[string]string{
						"line_number": m["line_number"], "conn_type": m["conn_type"],
						"databases": m["databases"], "address": m["address"], "netmask": m["netmask"],
						"auth_method": m["auth_method"], "options": m["options"],
						"parse_error": m["parse_error"],
					},
				})
			case "pg.settings":
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactAccountConfig,
					Subject: "server",
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: map[string]string{
						"name": m["name"], "setting": m["setting"], "unit": m["unit"],
					},
				})
			case "pg.role_settings":
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactAccountConfig,
					Subject: m["role_name"],
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: map[string]string{
						"database": m["database_name"], "settings": m["settings"],
					},
				})
			}
		}
	}
}
