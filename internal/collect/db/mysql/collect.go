package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"medaudit/internal/collect/db/dbutil"
	"medaudit/internal/facts"
)

const (
	collectVersion   = "0.2.0-m1"
	maxGrantsAccount = 200 // SHOW GRANTS 逐账号上限
)

// edgeKey 角色边去重键。
type edgeKey struct{ from, to string }

// Collect 运行全部 MySQL 模板，输出带收据的事实包。
// 固定模板 + 逐账号 SHOW GRANTS（语义解析）；权限不足/不支持标状态，不转空值。
func Collect(ctx context.Context, cfg Config) (*facts.FactBundle, error) {
	db, err := Connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	now := time.Now().UTC().Truncate(time.Second)
	b := &facts.FactBundle{
		SchemaVersion: facts.SchemaVersion,
		BundleID:      "bundle-mysql-" + now.Format("20060102-150405"),
		PlanID:        "plan-m1",
		Collector: facts.CollectorInfo{
			Name:           "medaudit-collector",
			Version:        collectVersion,
			Adapter:        facts.TargetDBMySQL,
			AdapterVersion: collectVersion,
		},
		CollectedAt: facts.TimeRange{Started: now},
		Scope: facts.Scope{
			HospitalID: "h-m1",
			AssetID:    fmt.Sprintf("mysql-%s:%d", cfg.Host, cfg.Port),
			TargetType: facts.TargetDBMySQL,
			Profile:    "m1-full",
		},
		Identities: facts.Identities{
			CollectorIdentity: cfg.User + "@collector",
			TargetIdentity:    "multiple@accounts",
			AppIdentitySource: "unknown",
		},
	}

	templates, err := LoadTemplates()
	if err != nil {
		return nil, err
	}

	seq := 0
	nextID := func() string { seq++; return fmt.Sprintf("mysql-fact-%06d", seq) }
	partial := false
	failed := false

	// default_roles 映射：account -> default role set（用于 role_edge 激活判定）。
	defaultRoles := map[string]map[string]bool{}
	// role_edges 原始边：去重后统一输出。
	edges := map[edgeKey]*facts.Fact{}

	addReceipt := func(t Template, r *dbutil.Rows, qerr error, start, end time.Time, paramDigest string) {
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
			partial = true
		case qerr != nil:
			rc.Status = "failed"
			rc.ErrorStage = "query"
			failed = true
		default:
			rc.RowCount = len(r.Data)
			if r.Truncated {
				rc.Truncated = true
				rc.Status = "partial"
				partial = true
			}
		}
		b.Receipts = append(b.Receipts, rc)
	}

	deniedMarker := func(t Template) {
		b.Facts = append(b.Facts, facts.Fact{
			FactID:  nextID(),
			Kind:    facts.FactAccountConfig,
			Subject: t.ID,
			Status:  facts.StatusPermissionDenied,
			Source:  t.ID,
		})
	}

	for _, t := range templates {
		if t.Dynamic {
			continue
		}
		start := time.Now()
		r, qerr := dbutil.QueryRows(ctx, db, t.SQL, 0, 0, 0)
		end := time.Now()
		addReceipt(t, r, qerr, start, end, "")
		if qerr != nil {
			if dbutil.IsPermissionDenied(qerr) {
				deniedMarker(t)
				continue
			}
			b.Execution = facts.ExecutionFailed
			b.CollectedAt.Finished = time.Now().UTC().Truncate(time.Second)
			return b, fmt.Errorf("template %s: %w", t.ID, qerr)
		}
		mapTemplate(t.ID, r, b, nextID, defaultRoles, edges)
	}

	// 逐账号 SHOW GRANTS（语义解析）。
	if err := collectShowGrants(ctx, db, b, nextID, addReceipt, &partial, &failed); err != nil {
		b.Execution = facts.ExecutionFailed
		b.CollectedAt.Finished = time.Now().UTC().Truncate(time.Second)
		return b, err
	}

	// 输出 role_edge（激活状态用 default_roles 判定）。
	for _, f := range edges {
		b.Facts = append(b.Facts, *f)
	}

	// 账号采集身份与被核查账号分开：记录本次实际连接账号。
	b.Facts = append(b.Facts, facts.Fact{
		FactID:     nextID(),
		Kind:       facts.FactIdentity,
		Subject:    cfg.User + "@collector-session",
		Status:     facts.StatusObserved,
		Source:     "mysql.session",
		Attributes: map[string]string{"note": "collector connection identity, not application identity"},
	})

	switch {
	case failed:
		b.Execution = facts.ExecutionFailed
	case partial:
		b.Execution = facts.ExecutionPartial
	default:
		b.Execution = facts.ExecutionComplete
	}
	b.CollectedAt.Finished = time.Now().UTC().Truncate(time.Second)
	if errs := b.Validate(); len(errs) != 0 {
		return b, fmt.Errorf("bundle validate: %v", errs)
	}
	return b, nil
}

// mapTemplate 将模板结果映射为事实。
func mapTemplate(tid string, r *dbutil.Rows, b *facts.FactBundle, nextID func() string,
	defaultRoles map[string]map[string]bool, edges map[edgeKey]*facts.Fact) {

	rowMap := func(i int) map[string]string {
		m := map[string]string{}
		for j, c := range r.Columns {
			m[strings.ToLower(c)] = r.Data[i][j]
		}
		return m
	}

	switch tid {
	case "mysql.accounts":
		for i := range r.Data {
			m := rowMap(i)
			subj := m["user"] + "@" + m["host"]
			b.Facts = append(b.Facts, facts.Fact{
				FactID:  nextID(),
				Kind:    facts.FactAccountConfig,
				Subject: subj,
				Status:  facts.StatusObserved,
				Source:  tid,
				Attributes: map[string]string{
					"plugin": m["plugin"], "has_auth_string": m["has_auth_string"],
					"account_locked": m["account_locked"], "password_expired": m["password_expired"],
					"password_last_changed": m["password_last_changed"], "password_lifetime": m["password_lifetime"],
				},
			})
		}
	case "mysql.account_tls":
		for i := range r.Data {
			m := rowMap(i)
			subj := m["user"] + "@" + m["host"]
			b.Facts = append(b.Facts, facts.Fact{
				FactID:  nextID(),
				Kind:    facts.FactAccountConfig,
				Subject: subj,
				Status:  facts.StatusObserved,
				Source:  tid,
				Attributes: map[string]string{
					"ssl_type": m["ssl_type"], "x509_issuer": m["x509_issuer"],
					"x509_subject": m["x509_subject"],
				},
			})
		}
	case "mysql.user_privs":
		for i := range r.Data {
			m := rowMap(i)
			subj := m["user"] + "@" + m["host"]
			grantable := m["grant_priv"] == "Y"
			for col, val := range m {
				if !strings.HasSuffix(col, "_priv") || col == "grant_priv" {
					continue
				}
				if val != "Y" {
					continue
				}
				priv := strings.ToUpper(strings.TrimSuffix(col, "_priv"))
				g := grantable
				b.Facts = append(b.Facts, facts.Fact{
					FactID:     nextID(),
					Kind:       facts.FactPrivilege,
					Subject:    subj,
					Status:     facts.StatusObserved,
					Source:     tid,
					Attributes: map[string]string{"privilege": priv},
					Scope:      "*.*",
					Activation: facts.ActivationDefault,
					Grantable:  &g,
				})
			}
		}
	case "mysql.global_grants":
		for i := range r.Data {
			m := rowMap(i)
			subj := m["user"] + "@" + m["host"]
			g := m["with_grant_option"] == "Y"
			b.Facts = append(b.Facts, facts.Fact{
				FactID:     nextID(),
				Kind:       facts.FactPrivilege,
				Subject:    subj,
				Status:     facts.StatusObserved,
				Source:     tid,
				Attributes: map[string]string{"privilege": m["privilege"], "dynamic": "true"},
				Scope:      "*.*",
				Activation: facts.ActivationDefault,
				Grantable:  &g,
			})
		}
	case "mysql.db_privs":
		for i := range r.Data {
			m := rowMap(i)
			subj := m["user"] + "@" + m["host"]
			scope := m["db"] + ".*"
			for col, val := range m {
				if !strings.HasSuffix(col, "_priv") {
					continue
				}
				if val != "Y" {
					continue
				}
				priv := strings.ToUpper(strings.TrimSuffix(col, "_priv"))
				b.Facts = append(b.Facts, facts.Fact{
					FactID:     nextID(),
					Kind:       facts.FactPrivilege,
					Subject:    subj,
					Status:     facts.StatusObserved,
					Source:     tid,
					Attributes: map[string]string{"privilege": priv},
					Scope:      scope,
					Activation: facts.ActivationDefault,
				})
			}
		}
	case "mysql.role_edges":
		for i := range r.Data {
			m := rowMap(i)
			from := m["from_user"] + "@" + m["from_host"]
			to := m["to_user"] + "@" + m["to_host"]
			admin := m["with_admin_option"] == "1" || strings.EqualFold(m["with_admin_option"], "Y")
			key := edgeKey{from, to}
			if _, ok := edges[key]; !ok {
				edges[key] = &facts.Fact{
					FactID:         nextID(),
					Kind:           facts.FactRoleEdge,
					Subject:        to,
					Status:         facts.StatusObserved,
					Source:         tid,
					PermissionPath: []string{from, to},
					Activation:     facts.ActivationUnknown,
					Attributes:     map[string]string{},
				}
			}
			edges[key].Attributes["with_admin_option"] = fmt.Sprintf("%v", admin)
		}
	case "mysql.default_roles":
		for i := range r.Data {
			m := rowMap(i)
			acct := m["user"] + "@" + m["host"]
			role := m["role_user"] + "@" + m["role_host"]
			if defaultRoles[acct] == nil {
				defaultRoles[acct] = map[string]bool{}
			}
			defaultRoles[acct][role] = true
			// 默认角色边直接输出（激活=默认）。
			b.Facts = append(b.Facts, facts.Fact{
				FactID:         nextID(),
				Kind:           facts.FactRoleEdge,
				Subject:        acct,
				Status:         facts.StatusObserved,
				Source:         tid,
				PermissionPath: []string{role, acct},
				Activation:     facts.ActivationDefault,
			})
		}
		// 回填 role_edges 的激活状态。
		for key, f := range edges {
			if defaultRoles[key.to] != nil && defaultRoles[key.to][key.from] {
				f.Activation = facts.ActivationDefault
			}
		}
	case "mysql.server_config":
		for i := range r.Data {
			m := rowMap(i)
			b.Facts = append(b.Facts, facts.Fact{
				FactID:  nextID(),
				Kind:    facts.FactAccountConfig,
				Subject: "global",
				Status:  facts.StatusObserved,
				Source:  tid,
				Attributes: map[string]string{
					"name": m["variable_name"], "value": m["variable_value"],
				},
			})
		}
	case "mysql.global_vars":
		for i := range r.Data {
			m := rowMap(i)
			b.Facts = append(b.Facts, facts.Fact{
				FactID:  nextID(),
				Kind:    facts.FactAccountConfig,
				Subject: "global",
				Status:  facts.StatusObserved,
				Source:  tid,
				Attributes: map[string]string{
					"mandatory_roles":             m["mandatory_roles"],
					"activate_all_roles_on_login": m["activate_all_roles_on_login"],
					"partial_revokes":             m["partial_revokes"],
				},
			})
		}
	}
}

// collectShowGrants 逐账号 SHOW GRANTS 并语义解析。
func collectShowGrants(ctx context.Context, db *sql.DB, b *facts.FactBundle, nextID func() string,
	addReceipt func(Template, *dbutil.Rows, error, time.Time, time.Time, string),
	partial, failed *bool) error {

	t := Template{ID: "mysql.show_grants", Version: "1"}
	// 从已采集的 accounts 事实取账号清单。
	var accounts []string
	seen := map[string]bool{}
	for _, f := range b.Facts {
		if f.Kind == facts.FactAccountConfig && f.Source == "mysql.accounts" && !seen[f.Subject] {
			seen[f.Subject] = true
			accounts = append(accounts, f.Subject)
		}
	}
	if len(accounts) > maxGrantsAccount {
		accounts = accounts[:maxGrantsAccount]
	}

	start := time.Now()
	totalStmts := 0
	truncated := false
	for _, acct := range accounts {
		parts := strings.SplitN(acct, "@", 2)
		if len(parts) != 2 {
			continue
		}
		stmt := "SHOW GRANTS FOR " + quoteAccount(parts[0], parts[1])
		r, qerr := dbutil.QueryRows(ctx, db, stmt, 0, 1000, 0)
		if qerr != nil {
			if dbutil.IsPermissionDenied(qerr) {
				*partial = true
				b.Facts = append(b.Facts, facts.Fact{
					FactID: nextID(), Kind: facts.FactPrivilege, Subject: acct,
					Status: facts.StatusPermissionDenied, Source: t.ID,
				})
				continue
			}
			end := time.Now()
			addReceipt(t, nil, qerr, start, end, "")
			*failed = true
			return fmt.Errorf("show grants for %s: %w", acct, qerr)
		}
		if r.Truncated {
			truncated = true
		}
		for i := range r.Data {
			grantStmt := r.Data[i][0]
			totalStmts++
			pg, perr := ParseShowGrant(grantStmt)
			if perr != nil {
				// 解析失败不丢弃：记录原文，标 inconsistent。
				b.Facts = append(b.Facts, facts.Fact{
					FactID: nextID(), Kind: facts.FactPrivilege, Subject: acct,
					Status: facts.StatusInconsistent, Source: t.ID,
					Attributes: map[string]string{"raw": trunc(grantStmt, 500), "parse_error": perr.Error()},
				})
				continue
			}
			emitParsedGrant(b, nextID, t.ID, pg)
		}
	}
	end := time.Now()
	rc := facts.Receipt{
		TemplateID: t.ID, TemplateVersion: t.Version,
		Started: start.UTC().Truncate(time.Second), Finished: end.UTC().Truncate(time.Second),
		DurationMs: end.Sub(start).Milliseconds(), RowCount: totalStmts,
		Status: "ok", Visibility: "full",
		ParamDigest: fmt.Sprintf("accounts=%d", len(accounts)),
	}
	if truncated {
		rc.Truncated = true
		rc.Status = "partial"
		*partial = true
	}
	b.Receipts = append(b.Receipts, rc)
	return nil
}

func emitParsedGrant(b *facts.FactBundle, nextID func() string, src string, pg *ParsedGrant) {
	subj := pg.GranteeUser + "@" + pg.GranteeHost
	if pg.IsRoleGrant {
		for _, r := range pg.Roles {
			b.Facts = append(b.Facts, facts.Fact{
				FactID:         nextID(),
				Kind:           facts.FactRoleEdge,
				Subject:        subj,
				Status:         facts.StatusObserved,
				Source:         src,
				PermissionPath: []string{r.String(), subj},
				Activation:     facts.ActivationUnknown,
			})
		}
		return
	}
	for _, p := range pg.Privs {
		g := pg.WithGrantOption
		attrs := map[string]string{"privilege": p}
		if pg.IsRevoke {
			// partial revokes：记录被撤销项，由规则引擎按产品语义抵扣正向授权。
			attrs["revoked"] = "true"
		}
		b.Facts = append(b.Facts, facts.Fact{
			FactID:     nextID(),
			Kind:       facts.FactPrivilege,
			Subject:    subj,
			Status:     facts.StatusObserved,
			Source:     src,
			Attributes: attrs,
			Scope:      pg.Scope,
			Activation: facts.ActivationDefault,
			Grantable:  &g,
		})
	}
}

// quoteAccount 安全引用账号字面量（仅固定语句形状 SHOW GRANTS FOR 'u'@'h'）。
func quoteAccount(user, host string) string {
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	return q(user) + "@" + q(host)
}
