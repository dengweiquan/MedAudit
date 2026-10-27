// Package correlation 跨层权限路径关联分析（M8-1）。
//
// 把同一医院的多个事实包（OS/DB/中间件）建成权限图：节点是主体（用户/组/账号）
// 与资源（文件/中间件实例），边是「成员/sudo/可写/控制/以…运行」关系，
// 每条边都引用产生它的事实 ID。随后从低权主体出发 BFS 搜索到高价值目标
// （root/SYSTEM/数据库超级账号）的最短提权路径。
// 纪律：没有事实证据的链路不生成；跨包身份按名匹配（同主机由分析者选包时确认）。
package correlation

import (
	"sort"
	"strconv"
	"strings"

	"medaudit/internal/facts"
)

// BundleInput 一个待关联的事实包。
type BundleInput struct {
	BundleID string
	Adapter  string
	AssetID  string
	Hospital string
	Facts    []facts.Fact
}

// Hop 路径中的一步。
type Hop struct {
	From     string   `json:"from"`
	Action   string   `json:"action"`
	To       string   `json:"to"`
	BundleID string   `json:"bundle_id"`
	Evidence []string `json:"evidence"`
}

// PathResult 一条提权路径。
type PathResult struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Risk   string `json:"risk"`
	Hops   []Hop  `json:"hops"`
}

// Report 关联分析结果。
type Report struct {
	Bundles int          `json:"bundles"`
	Nodes   int          `json:"nodes"`
	Edges   int          `json:"edges"`
	Paths   []PathResult `json:"paths"`
}

type edge struct {
	from, to, action, bundleID string
	evidence                   []string
}

type graph struct {
	nodes   map[string]string // id -> label
	adj     map[string][]edge
	edges   int
	highDB  map[string]bool // 高权 DB 账号节点
	targets map[string]bool
}

// ---- 节点 ID 规范化 ----

func userNode(name string) string {
	name = strings.TrimSpace(name)
	// Windows 账户名归一：NT AUTHORITY\SYSTEM -> SYSTEM，HOST\user -> user
	if i := strings.LastIndex(name, "\\"); i >= 0 {
		name = name[i+1:]
	}
	return "user:" + name
}

func groupNode(name string) string { return "group:" + name }

// winShort 去掉 Windows 名称的域/机器前缀（MEDAUDIT\HIS-DBA -> HIS-DBA）。
func winShort(name string) string {
	if i := strings.LastIndex(name, "\\"); i >= 0 {
		return name[i+1:]
	}
	return name
}
func fileNode(path string) string { return "file:" + path }
func mwNode(asset string) string  { return "mw:" + asset }
func dbAcctNode(adapter, acct string) string {
	return "dbacct:" + adapter + ":" + acct
}
func dbRoleNode(adapter, role string) string {
	return "dbrole:" + adapter + ":" + role
}

func isRootUser(id string) bool {
	return id == "user:root" || id == "user:SYSTEM" || id == "user:Administrator"
}

// Analyze 构建图并搜索提权路径。
func Analyze(inputs []BundleInput) *Report {
	g := &graph{
		nodes:   map[string]string{},
		adj:     map[string][]edge{},
		highDB:  map[string]bool{},
		targets: map[string]bool{"user:root": true, "user:SYSTEM": true},
	}
	// uid/gid -> 名称（来自同批 OS 包的 passwd/groups 事实）
	uidName := map[string]string{}
	gidName := map[string]string{}
	for _, in := range inputs {
		for _, f := range in.Facts {
			if f.Source == "linux.passwd" {
				uidName[f.Attributes["uid"]] = f.Subject
			}
			if f.Source == "linux.groups" && f.Attributes["entity"] == "group" {
				gidName[f.Attributes["gid"]] = f.Subject
			}
		}
	}
	resolveUID := func(uid string) string {
		if uid == "0" {
			return "root"
		}
		if n, ok := uidName[uid]; ok {
			return n
		}
		return "uid:" + uid
	}
	resolveGroup := func(attrs map[string]string) string {
		if attrs["group"] != "" {
			return groupNode(attrs["group"])
		}
		if gid := attrs["gid"]; gid != "" {
			if n, ok := gidName[gid]; ok {
				return groupNode(n)
			}
			return groupNode("gid:" + gid)
		}
		return ""
	}

	addNode := func(id, label string) {
		if _, ok := g.nodes[id]; !ok {
			g.nodes[id] = label
		}
	}
	addEdge := func(from, to, action, bundleID, factID string) {
		addNode(from, from)
		addNode(to, to)
		g.adj[from] = append(g.adj[from], edge{from, to, action, bundleID, []string{factID}})
		g.edges++
	}
	// 组登录待链接：DB 包里以 DOMAIN\Group 形式出现的组登录，
	// 待全部包处理完、组节点齐备后再与 OS 包的组节点连边。
	type pendingLink struct{ group, acctNode, bundleID, factID string }
	var pending []pendingLink
	noteLogin := func(subject, nodeID, bundleID, factID string) {
		if strings.Contains(subject, "\\") {
			pending = append(pending, pendingLink{winShort(subject), nodeID, bundleID, factID})
		}
	}

	for _, in := range inputs {
		adapter := in.Adapter
		mwInst := mwNode(in.AssetID)
		// 先确定本包的 DB 角色集合（role_edge 的 path[0]）
		roles := map[string]bool{}
		winGroups := map[string]bool{}
		for _, f := range in.Facts {
			if f.Kind == facts.FactRoleEdge && len(f.PermissionPath) > 0 {
				roles[f.PermissionPath[0]] = true
				winGroups[winShort(f.PermissionPath[0])] = true
			}
		}
		for _, f := range in.Facts {
			switch {
			// ---- 组成员（Linux） ----
			case f.Kind == facts.FactRoleEdge && f.Source == "linux.groups" && len(f.PermissionPath) > 0:
				addEdge(userNode(f.Subject), groupNode(f.PermissionPath[0]), "成员", in.BundleID, f.FactID)

			// ---- sudo ----
			case f.Kind == facts.FactAccountConfig && f.Source == "linux.sudo" &&
				f.Status == facts.StatusObserved && f.Attributes["present"] != "false":
				who := f.Subject
				from := userNode(who)
				if strings.HasPrefix(who, "%") {
					from = groupNode(strings.TrimPrefix(who, "%"))
				}
				runas := strings.Trim(f.Attributes["runas"], "()")
				if runas == "" || runas == "ALL" || runas == "root" {
					runas = "root"
				} else if i := strings.Index(runas, ":"); i >= 0 {
					runas = runas[:i]
				}
				action := "sudo"
				if f.Attributes["commands_all"] == "true" {
					action = "sudo(ALL)"
				}
				addEdge(from, userNode(runas), action, in.BundleID, f.FactID)

			// ---- Windows 本地/域组成员 ----
			case f.Kind == facts.FactRoleEdge && adapter == "os-windows" && len(f.PermissionPath) > 0 &&
				f.Status == facts.StatusObserved:
				from := userNode(f.Subject)
				if winGroups[winShort(f.Subject)] {
					from = groupNode(winShort(f.Subject))
				}
				addEdge(from, groupNode(winShort(f.PermissionPath[0])), "成员", in.BundleID, f.FactID)

			// ---- DB 角色成员 ----
			case f.Kind == facts.FactRoleEdge && strings.HasPrefix(adapter, "db-") && len(f.PermissionPath) > 0:
				role := f.PermissionPath[0]
				from := dbAcctNode(adapter, f.Subject)
				if roles[f.Subject] {
					from = dbRoleNode(adapter, f.Subject)
				}
				addEdge(from, dbRoleNode(adapter, role), "持有角色", in.BundleID, f.FactID)
				noteLogin(f.Subject, from, in.BundleID, f.FactID)
				if isSuperRole(adapter, role) {
					// 提权终点是超级角色本身：低权账号经角色链到达它即构成路径
					g.highDB[dbRoleNode(adapter, role)] = true
					g.targets[dbRoleNode(adapter, role)] = true
				}

			// ---- DB 权限（仅用于高权标记） ----
			case f.Kind == facts.FactPrivilege && strings.HasPrefix(adapter, "db-"):
				subj := dbAcctNode(adapter, f.Subject)
				if roles[f.Subject] {
					subj = dbRoleNode(adapter, f.Subject)
				}
				noteLogin(f.Subject, subj, in.BundleID, f.FactID)
				if isSuperPrivilege(adapter, f.Attributes["privilege"]) {
					g.highDB[subj] = true
					g.targets[subj] = true
				}

			// ---- PG 超级用户（identity/account_config 属性） ----
			case adapter == "db-postgres" && (f.Kind == facts.FactIdentity || f.Kind == facts.FactAccountConfig):
				if f.Attributes["is_superuser"] == "true" || f.Attributes["superuser"] == "true" || f.Attributes["rolsuper"] == "true" {
					n := dbAcctNode(adapter, f.Subject)
					g.highDB[n] = true
					g.targets[n] = true
				}

			// ---- 文件可写（OS / MW 通用） ----
			case f.Kind == facts.FactFilePerm:
				fn := fileNode(f.Subject)
				if f.Attributes["writable_by_other"] == "true" {
					addEdge("user:*", fn, "可写(other)", in.BundleID, f.FactID)
				}
				if f.Attributes["writable_by_group"] == "true" {
					if gn := resolveGroup(f.Attributes); gn != "" {
						addEdge(gn, fn, "可写(group)", in.BundleID, f.FactID)
					}
				}
				// 中间件配置文件 → 控制该中间件实例
				if strings.HasPrefix(adapter, "mw-") && adapter != "mw-iis" {
					addEdge(fn, mwInst, "可篡改配置/部署", in.BundleID, f.FactID)
				}
				// Windows ACL 低权可写
				if f.Attributes["writable_by_low_priv"] == "true" {
					addEdge("user:*", fn, "可写(低权)", in.BundleID, f.FactID)
				}

			// ---- 进程以某身份运行 ----
			case f.Kind == facts.FactProcess:
				if exe := f.Attributes["exe"]; exe != "" && f.Attributes["euid"] != "" {
					addEdge(fileNode(exe), userNode(resolveUID(f.Attributes["euid"])), "以该身份运行", in.BundleID, f.FactID)
				}
				if bp := f.Attributes["binary_path"]; bp != "" && f.Attributes["actual_user"] != "" {
					addEdge(fileNode(firstToken(bp)), userNode(f.Attributes["actual_user"]), "以该身份运行", in.BundleID, f.FactID)
				}
				if ru := f.Attributes["run_user"]; ru != "" && strings.HasPrefix(adapter, "mw-") {
					addEdge(mwInst, userNode(ru), "以该身份运行", in.BundleID, f.FactID)
				}

			// ---- Windows 服务运行身份 ----
			case f.Kind == facts.FactServiceConfig && adapter == "os-windows":
				if bp := f.Attributes["binary_path"]; bp != "" && f.Attributes["service_account"] != "" {
					addEdge(fileNode(firstToken(bp)), userNode(f.Attributes["service_account"]), "服务以该身份运行", in.BundleID, f.FactID)
				}

			// ---- Tomcat 控制台账号 ----
			case f.Kind == facts.FactIdentity && adapter == "mw-tomcat":
				acct := "mwacct:" + in.AssetID + ":" + f.Subject
				addNode(acct, acct)
				// 只有管理角色能经控制台部署应用=以运行身份执行代码，才构成提权边；
				// 只读类角色（如 manager-status）的访问本身不是提权步骤，不建边。
				if hasAdminRole(f.Attributes["roles"]) {
					addEdge(acct, mwInst, "控制台管理", in.BundleID, f.FactID)
				}
			}
		}
	}

	// 组登录链接解析：DB 中的组登录账号与同名 OS 组节点连边
	for _, pl := range pending {
		gn := groupNode(pl.group)
		if _, ok := g.nodes[gn]; ok {
			addEdge(gn, pl.acctNode, "组登录", pl.bundleID, pl.factID)
		}
	}

	// DB 角色的高权性经成员链传播：角色节点本身也是目标（路径终点取账号即可，
	// BFS 目标集合含高权角色节点与高权账号节点）
	for n := range g.highDB {
		g.targets[n] = true
	}

	paths := g.search()
	return &Report{Bundles: len(inputs), Nodes: len(g.nodes), Edges: g.edges, Paths: paths}
}

// search 从每个低权源出发 BFS 到任一目标，取最短路径（每对源-目标一条）。
func (g *graph) search() []PathResult {
	var sources []string
	for id := range g.nodes {
		if g.targets[id] || isRootUser(id) {
			continue
		}
		// 内置管理员账号本身即高权，不作路径源（从它出发的路径没有信息量）
		if strings.HasPrefix(id, "dbacct:") {
			acct := id[strings.LastIndex(id, ":")+1:]
			if acct == "SYS" || acct == "SYSTEM" || acct == "sa" || acct == "postgres" {
				continue
			}
		}
		if strings.HasPrefix(id, "user:") || strings.HasPrefix(id, "group:") ||
			strings.HasPrefix(id, "mwacct:") || strings.HasPrefix(id, "dbacct:") {
			sources = append(sources, id)
		}
	}
	sort.Strings(sources)
	var results []PathResult
	seen := map[string]bool{}
	type prev struct {
		node string
		e    edge
	}
	for _, src := range sources {
		dist := map[string]int{src: 0}
		prevOf := map[string]prev{}
		queue := []string{src}
		var found []string
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if dist[cur] >= 5 {
				continue
			}
			for _, e := range g.adj[cur] {
				if _, ok := dist[e.to]; ok {
					continue
				}
				dist[e.to] = dist[cur] + 1
				prevOf[e.to] = prev{cur, e}
				queue = append(queue, e.to)
				if g.targets[e.to] {
					found = append(found, e.to)
				}
			}
		}
		for _, tgt := range found {
			// 回溯路径
			var hops []Hop
			for n := tgt; n != src; {
				p := prevOf[n]
				hops = append([]Hop{{
					From: p.node, Action: p.e.action, To: n,
					BundleID: p.e.bundleID, Evidence: p.e.evidence,
				}}, hops...)
				n = p.node
			}
			key := src + ">" + tgt + ">" + strconv.Itoa(len(hops))
			if seen[key] {
				continue
			}
			seen[key] = true
			risk := "medium"
			if len(hops) <= 3 {
				risk = "high"
			}
			results = append(results, PathResult{Source: src, Target: tgt, Risk: risk, Hops: hops})
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if len(results[i].Hops) != len(results[j].Hops) {
			return len(results[i].Hops) < len(results[j].Hops)
		}
		return results[i].Source+results[i].Target < results[j].Source+results[j].Target
	})
	if len(results) > 100 {
		results = results[:100]
	}
	return results
}

func firstToken(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "\"") {
		if end := strings.Index(s[1:], "\""); end >= 0 {
			return s[1 : 1+end]
		}
	}
	if i := strings.Index(s, " "); i >= 0 {
		return s[:i]
	}
	return s
}

func hasAdminRole(roles string) bool {
	admin := map[string]bool{
		"manager-gui": true, "manager-script": true, "manager-jmx": true,
		"admin-gui": true, "admin-script": true,
	}
	for _, r := range strings.Split(roles, ",") {
		if admin[strings.TrimSpace(r)] {
			return true
		}
	}
	return false
}

// isSuperRole 各引擎的超级角色。
func isSuperRole(adapter, role string) bool {
	switch adapter {
	case "db-oracle":
		return strings.EqualFold(role, "DBA")
	case "db-sqlserver":
		return strings.EqualFold(role, "sysadmin")
	}
	return false
}

// isSuperPrivilege 各引擎的超级权限名。
func isSuperPrivilege(adapter, priv string) bool {
	p := strings.ToUpper(strings.TrimSpace(priv))
	switch adapter {
	case "db-mysql":
		return p == "SUPER" || p == "ALL PRIVILEGES"
	case "db-oracle":
		return p == "SYSDBA" || strings.HasPrefix(p, "GRANT ANY")
	case "db-postgres":
		return p == "SUPERUSER"
	}
	return false
}
