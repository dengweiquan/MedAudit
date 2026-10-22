package oracle

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
	maxRoleDepth   = 8   // 角色传递闭包最大深度
	maxTransEdges  = 500 // 单主体传递边上限
)

// roleEdge 原始角色授予边。
type roleEdge struct {
	grantee     string
	role        string
	adminOption bool
	defaultRole bool // DEFAULT_ROLE='YES'
}

// Collect 运行全部 Oracle 模板，输出带收据的事实包。
// 角色嵌套在采集侧展开（直接边 + 传递边）；DBA 角色与 SYSDBA 严格区分。
func Collect(ctx context.Context, cfg Config) (*facts.FactBundle, error) {
	db, err := Connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	now := time.Now().UTC().Truncate(time.Second)
	b := &facts.FactBundle{
		SchemaVersion: facts.SchemaVersion,
		BundleID:      "bundle-ora-" + now.Format("20060102-150405"),
		PlanID:        "plan-m1",
		Collector: facts.CollectorInfo{
			Name:           "medaudit-collector",
			Version:        collectVersion,
			Adapter:        facts.TargetDBOracle,
			AdapterVersion: collectVersion,
		},
		CollectedAt: facts.TimeRange{Started: now},
		Scope: facts.Scope{
			HospitalID: "h-m1",
			AssetID:    fmt.Sprintf("oracle-%s:%d/%s", cfg.Host, cfg.Port, cfg.Service),
			TargetType: facts.TargetDBOracle,
			Instance:   "ARK19C",
			Container:  cfg.Service,
			Profile:    "m1-full",
		},
		Identities: facts.Identities{
			CollectorIdentity: cfg.User + "@collector",
			TargetIdentity:    "multiple@users",
			AppIdentitySource: "unknown",
		},
	}

	templates, err := LoadTemplates()
	if err != nil {
		return nil, err
	}

	seq := 0
	nextID := func() string { seq++; return fmt.Sprintf("ora-fact-%06d", seq) }
	failed := false

	var users []string
	var edges []roleEdge

	run := func(t Template, mapFn func(*dbutil.Rows, *[]string, *[]roleEdge)) error {
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
				FactID: nextID(), Kind: facts.FactAccountConfig, Subject: t.ID,
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
			mapFn(r, &users, &edges)
			return nil
		}
	}

	var cdbTemplates []Template
	for _, t := range templates {
		if strings.HasPrefix(t.ID, "ora.cdb_") {
			cdbTemplates = append(cdbTemplates, t)
			continue
		}
		mapFn := mapTemplate(t.ID, b, nextID)
		if err := run(t, mapFn); err != nil {
			return finish(b, failed, err)
		}
	}

	// CDB 跨容器模板：仅当连接位于 CDB$ROOT 时才跑（探针：SYS_CONTEXT CON_NAME）。
	if len(cdbTemplates) > 0 {
		rStart := time.Now()
		rc := facts.Receipt{
			TemplateID: "ora.cdb_context", TemplateVersion: "1",
			Started: rStart.UTC().Truncate(time.Second),
			Status: "ok", Visibility: "full",
		}
		prows, perr := dbutil.QueryRows(ctx, db,
			"SELECT SYS_CONTEXT('USERENV', 'CON_NAME') AS con_name FROM DUAL", 0, 0, 0)
		conName := ""
		if perr == nil && len(prows.Data) > 0 {
			conName = prows.Data[0][prows.ColIndex("con_name")]
			rc.RowCount = 1
		}
		if perr != nil {
			rc.Status = "failed"
			rc.ErrorStage = "query"
			failed = true
		}
		rc.Finished = time.Now().UTC().Truncate(time.Second)
		rc.DurationMs = rc.Finished.Sub(rc.Started).Milliseconds()
		b.Receipts = append(b.Receipts, rc)
		if perr == nil && conName == "CDB$ROOT" {
			for _, t := range cdbTemplates {
				mapFn := mapTemplate(t.ID, b, nextID)
				if err := run(t, mapFn); err != nil {
					return finish(b, failed, err)
				}
			}
		}
	}

	// 角色传递闭包：直接边已输出，此处输出传递边。
	emitTransitiveEdges(b, nextID, users, edges)

	b.Facts = append(b.Facts, facts.Fact{
		FactID:     nextID(),
		Kind:       facts.FactIdentity,
		Subject:    cfg.User + "@collector-session",
		Status:     facts.StatusObserved,
		Source:     "ora.session",
		Attributes: map[string]string{"note": "collector connection identity, not application identity"},
	})

	return finish(b, failed, nil)
}

func finish(b *facts.FactBundle, failed bool, err error) (*facts.FactBundle, error) {
	if err != nil || failed {
		b.Execution = facts.ExecutionFailed
	} else {
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

func rowMap(r *dbutil.Rows, i int) map[string]string {
	m := map[string]string{}
	for j, c := range r.Columns {
		m[strings.ToLower(c)] = r.Data[i][j]
	}
	return m
}

func mapTemplate(tid string, b *facts.FactBundle, nextID func() string) func(*dbutil.Rows, *[]string, *[]roleEdge) {
	return func(r *dbutil.Rows, users *[]string, edges *[]roleEdge) {
		for i := range r.Data {
			m := rowMap(r, i)
			switch tid {
			case "ora.users":
				*users = append(*users, m["username"])
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactAccountConfig,
					Subject: m["username"],
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: map[string]string{
						"account_status": m["account_status"], "authentication_type": m["authentication_type"],
						"profile": m["profile"], "created": m["created"],
					},
				})
			case "ora.role_privs":
				e := roleEdge{
					grantee:     m["grantee"],
					role:        m["granted_role"],
					adminOption: strings.EqualFold(m["admin_option"], "YES"),
					defaultRole: strings.EqualFold(m["default_role"], "YES"),
				}
				*edges = append(*edges, e)
				act := facts.ActivationConditional
				if e.defaultRole {
					act = facts.ActivationDefault
				}
				b.Facts = append(b.Facts, facts.Fact{
					FactID:         nextID(),
					Kind:           facts.FactRoleEdge,
					Subject:        e.grantee,
					Status:         facts.StatusObserved,
					Source:         tid,
					PermissionPath: []string{e.role, e.grantee},
					Activation:     act,
					Attributes:     map[string]string{"admin_option": fmt.Sprintf("%v", e.adminOption)},
				})
			case "ora.sys_privs":
				g := strings.EqualFold(m["admin_option"], "YES")
				b.Facts = append(b.Facts, facts.Fact{
					FactID:     nextID(),
					Kind:       facts.FactPrivilege,
					Subject:    m["grantee"],
					Status:     facts.StatusObserved,
					Source:     tid,
					Attributes: map[string]string{"privilege": m["privilege"]},
					Scope:      "instance",
					Activation: facts.ActivationDefault,
					Grantable:  &g,
				})
			case "ora.tab_privs":
				g := strings.EqualFold(m["grantable"], "YES")
				b.Facts = append(b.Facts, facts.Fact{
					FactID:     nextID(),
					Kind:       facts.FactPrivilege,
					Subject:    m["grantee"],
					Status:     facts.StatusObserved,
					Source:     tid,
					Attributes: map[string]string{"privilege": m["privilege"]},
					Scope:      m["owner"] + "." + m["table_name"],
					Activation: facts.ActivationDefault,
					Grantable:  &g,
				})
			case "ora.cdb_users":
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactAccountConfig,
					Subject: m["username"],
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: map[string]string{
						"account_status": m["account_status"], "common": m["common"],
						"oracle_maintained": m["oracle_maintained"], "con_id": m["con_id"],
					},
					Scope: "container:" + m["con_id"],
				})
			case "ora.cdb_role_privs":
				e := roleEdge{
					grantee:     m["grantee"],
					role:        m["granted_role"],
					adminOption: strings.EqualFold(m["admin_option"], "YES"),
					defaultRole: strings.EqualFold(m["default_role"], "YES"),
				}
				act := facts.ActivationConditional
				if e.defaultRole {
					act = facts.ActivationDefault
				}
				b.Facts = append(b.Facts, facts.Fact{
					FactID:         nextID(),
					Kind:           facts.FactRoleEdge,
					Subject:        e.grantee,
					Status:         facts.StatusObserved,
					Source:         tid,
					PermissionPath: []string{e.role, e.grantee},
					Activation:     act,
					Attributes: map[string]string{
						"admin_option": fmt.Sprintf("%v", e.adminOption),
						"common":       m["common"], "con_id": m["con_id"],
					},
					Scope: "container:" + m["con_id"],
				})
			case "ora.cdb_sys_privs":
				g := strings.EqualFold(m["admin_option"], "YES")
				b.Facts = append(b.Facts, facts.Fact{
					FactID:     nextID(),
					Kind:       facts.FactPrivilege,
					Subject:    m["grantee"],
					Status:     facts.StatusObserved,
					Source:     tid,
					Attributes: map[string]string{
						"privilege": m["privilege"], "common": m["common"], "con_id": m["con_id"],
					},
					Scope:      "container:" + m["con_id"],
					Activation: facts.ActivationDefault,
					Grantable:  &g,
				})
			case "ora.profiles":
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactAccountConfig,
					Subject: m["profile"],
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: map[string]string{
						"resource": m["resource_name"], "limit": m["limit_value"],
					},
				})
			case "ora.pwfile_users":
				// SYSDBA/SYSOPER 等管理授权：DBA 角色不等于 SYSDBA，单独建模。
				b.Facts = append(b.Facts, facts.Fact{
					FactID:  nextID(),
					Kind:    facts.FactPrivilege,
					Subject: m["username"],
					Status:  facts.StatusObserved,
					Source:  tid,
					Attributes: map[string]string{
						"sysdba": m["sysdba"], "sysoper": m["sysoper"], "sysasm": m["sysasm"],
						"sysbackup": m["sysbackup"], "sysdg": m["sysdg"], "syskm": m["syskm"],
					},
					Scope:      "instance",
					Activation: facts.ActivationDefault,
				})
			}
		}
	}
}

// emitTransitiveEdges 计算角色传递闭包并输出传递边事实。
// 直接边已在 mapTemplate 输出；此处只输出路径长度 >1 的边，激活一律标条件（保守）。
func emitTransitiveEdges(b *facts.FactBundle, nextID func() string, users []string, edges []roleEdge) {
	userSet := map[string]bool{}
	for _, u := range users {
		userSet[u] = true
	}
	// 邻接表：grantee -> roles
	adj := map[string][]roleEdge{}
	for _, e := range edges {
		adj[e.grantee] = append(adj[e.grantee], e)
	}
	for _, u := range users {
		count := 0
		// BFS：(当前节点, 路径)
		type item struct {
			node string
			path []string
		}
		visited := map[string]bool{u: true}
		queue := []item{}
		for _, e := range adj[u] {
			queue = append(queue, item{node: e.role, path: []string{u, e.role}})
		}
		for len(queue) > 0 && count < maxTransEdges {
			cur := queue[0]
			queue = queue[1:]
			if len(cur.path)-1 > 1 {
				// 传递边：路径反转为 角色->...->用户 的权限来源路径。
				pp := make([]string, len(cur.path))
				for i, n := range cur.path {
					pp[len(cur.path)-1-i] = n
				}
				b.Facts = append(b.Facts, facts.Fact{
					FactID:         nextID(),
					Kind:           facts.FactRoleEdge,
					Subject:        u,
					Status:         facts.StatusObserved,
					Source:         "ora.role_privs",
					PermissionPath: pp,
					Activation:     facts.ActivationConditional,
					Attributes:     map[string]string{"transitive": "true"},
				})
				count++
			}
			if len(cur.path) > maxRoleDepth {
				continue
			}
			for _, e := range adj[cur.node] {
				if !visited[e.role] {
					visited[e.role] = true
					np := append(append([]string{}, cur.path...), e.role)
					queue = append(queue, item{node: e.role, path: np})
				}
			}
		}
	}
}
