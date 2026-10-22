package rules

import (
	"sort"
	"strings"

	"medaudit/internal/facts"
)

// 有效权限求解（M8-2）：在事实包内对角色边做传递闭包，
// 回答「主体经角色链实际持有哪些角色与权限」。
// 单看直接授权会漏掉经角色/组间接获得的高权——多条规则与关联引擎共用本求解器。
//
// 语义边界：
//   - MySQL 角色需激活才生效；采集端 activation=unknown 时纳入计算并在结果中标注，
//     由判读者结合现场确认（不静默丢弃，也不冒充确定）。
//   - PostgreSQL 的角色属性（superuser/createdb 等）按 PG 语义不可继承，
//     本求解器只传播对象/库级权限事实，属性判定仍走 identity 事实直查。
//   - SQL Server 的 DENY 在适配器层已体现为独立的权限事实状态；
//     角色成员关系不受 DENY 影响（DENY 不能否决固定角色成员资格）。

// RolePath 主体到某角色的一条持有路径（主体在首，角色在尾）。
type RolePath struct {
	Role       string   `json:"role"`
	Path       []string `json:"path"`
	Evidence   []string `json:"evidence"`
	Activation string   `json:"activation,omitempty"`
}

// EffPriv 一条有效权限（直接或经角色派生）。
type EffPriv struct {
	Privilege string   `json:"privilege"`
	Scope     string   `json:"scope,omitempty"`
	Direct    bool     `json:"direct"`
	Via       []string `json:"via,omitempty"`
	Evidence  []string `json:"evidence"`
}

// EffectiveIndex 事实包内的角色/权限索引。
type EffectiveIndex struct {
	edges map[string][]roleGrant // grantee -> grants
	privs map[string][]facts.Fact
	roles map[string]bool // 出现过的角色名集合
}

type roleGrant struct {
	role       string
	activation string
	factID     string
}

// BuildEffectiveIndex 从事实集合构建索引（规则与平台 API 共用）。
func BuildEffectiveIndex(all []facts.Fact) *EffectiveIndex {
	ix := &EffectiveIndex{
		edges: map[string][]roleGrant{},
		privs: map[string][]facts.Fact{},
		roles: map[string]bool{},
	}
	for _, f := range all {
		switch f.Kind {
		case facts.FactRoleEdge:
			if len(f.PermissionPath) == 0 {
				continue
			}
			role := f.PermissionPath[0]
			ix.roles[role] = true
			ix.edges[f.Subject] = append(ix.edges[f.Subject], roleGrant{
				role: role, activation: string(f.Activation), factID: f.FactID,
			})
		case facts.FactPrivilege:
			ix.privs[f.Subject] = append(ix.privs[f.Subject], f)
		}
	}
	return ix
}

// RolesOf 返回主体传递持有的全部角色及一条见证路径。maxDepth 防环。
func (ix *EffectiveIndex) RolesOf(subject string) []RolePath {
	type item struct {
		role, act string
		path      []string
		evidence  []string
	}
	found := map[string]item{}
	queue := []item{}
	for _, g := range ix.edges[subject] {
		queue = append(queue, item{g.role, g.activation, []string{subject, g.role}, []string{g.factID}})
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if _, ok := found[cur.role]; ok {
			continue
		}
		found[cur.role] = cur
		if len(cur.path) >= 8 {
			continue
		}
		for _, g := range ix.edges[cur.role] {
			queue = append(queue, item{
				g.role, g.activation,
				append(append([]string{}, cur.path...), g.role),
				append(append([]string{}, cur.evidence...), g.factID),
			})
		}
	}
	out := make([]RolePath, 0, len(found))
	for _, it := range found {
		out = append(out, RolePath{Role: it.role, Path: it.path, Evidence: it.evidence, Activation: it.act})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Role < out[j].Role })
	return out
}

// PrivilegesOf 返回主体的有效权限：直接授权 + 经持有角色派生的授权。
func (ix *EffectiveIndex) PrivilegesOf(subject string) []EffPriv {
	var out []EffPriv
	seen := map[string]bool{}
	key := func(p EffPriv) string {
		return p.Privilege + "|" + p.Scope + "|" + strings.Join(p.Via, ">")
	}
	for _, f := range ix.privs[subject] {
		ep := EffPriv{
			Privilege: privName(f), Scope: string(f.Scope),
			Direct: true, Evidence: []string{f.FactID},
		}
		if !seen[key(ep)] {
			seen[key(ep)] = true
			out = append(out, ep)
		}
	}
	for _, rp := range ix.RolesOf(subject) {
		for _, f := range ix.privs[rp.Role] {
			ep := EffPriv{
				Privilege: privName(f), Scope: string(f.Scope),
				Direct: false, Via: rp.Path, Evidence: append(append([]string{}, rp.Evidence...), f.FactID),
			}
			if !seen[key(ep)] {
				seen[key(ep)] = true
				out = append(out, ep)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Privilege != out[j].Privilege {
			return out[i].Privilege < out[j].Privilege
		}
		return out[i].Scope < out[j].Scope
	})
	return out
}

// Subjects 返回索引中出现过的全部主体（授权对象与角色边被授予者）。
func (ix *EffectiveIndex) Subjects() []string {
	set := map[string]bool{}
	for s := range ix.privs {
		set[s] = true
	}
	for s := range ix.edges {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// privName 权限名兼容：多数引擎用 privilege，SQL Server 用 permission。
func privName(f facts.Fact) string {
	if v := f.Attributes["privilege"]; v != "" {
		return v
	}
	return f.Attributes["permission"]
}

// IsRole 主体名是否为已知角色。
func (ix *EffectiveIndex) IsRole(name string) bool { return ix.roles[name] }
