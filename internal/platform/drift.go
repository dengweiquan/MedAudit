package platform

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"medaudit/internal/facts"
)

// DriftItem 一条包间差异（新增或消失的稳定事实）。
type DriftItem struct {
	Kind     string `json:"kind"`
	Source   string `json:"source"`
	Subject  string `json:"subject"`
	Category string `json:"category"`
	Detail   string `json:"detail"`
}

// DriftReport 两包漂移对比结果（M8-4）。
type DriftReport struct {
	BaseID       string      `json:"base_id"`
	CompareID    string      `json:"compare_id"`
	AssetID      string      `json:"asset_id"`
	Adapter      string      `json:"adapter"`
	Added        []DriftItem `json:"added"`
	Removed      []DriftItem `json:"removed"`
	AddedTotal   int         `json:"added_total"`
	RemovedTotal int         `json:"removed_total"`
	Attention    int         `json:"attention"` // 新增授权+新增角色关系条数（重点关注）
}

// driftKinds 参与漂移对比的事实类型：只取权限语义稳定者；
// process（pid 每次都变）等瞬时事实不入漂移，避免噪声淹没真实变化。
var driftKinds = map[facts.FactKind]bool{
	facts.FactIdentity: true, facts.FactPrivilege: true, facts.FactRoleEdge: true,
	facts.FactAccountConfig: true, facts.FactFilePerm: true, facts.FactServiceConfig: true,
}

// volatileAttrs 签名计算时剔除的易变属性（重启/运行态抖动，非权限变化）。
var volatileAttrs = map[string]bool{
	"pid": true, "ppid": true, "boot_id": true,
	"active_state": true, "sub_state": true, "state": true,
}

func driftSignature(f facts.Fact) string {
	keys := make([]string, 0, len(f.Attributes))
	for k := range f.Attributes {
		if !volatileAttrs[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString(string(f.Kind))
	sb.WriteByte('|')
	sb.WriteString(f.Source)
	sb.WriteByte('|')
	sb.WriteString(f.Subject)
	sb.WriteByte('|')
	sb.WriteString(string(f.Scope))
	sb.WriteByte('|')
	sb.WriteString(strings.Join(f.PermissionPath, ">"))
	for _, k := range keys {
		sb.WriteByte('|')
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(f.Attributes[k])
	}
	return sb.String()
}

func driftCategory(kind facts.FactKind, added bool) string {
	if added {
		switch kind {
		case facts.FactPrivilege:
			return "新增授权"
		case facts.FactRoleEdge:
			return "新增角色关系"
		case facts.FactIdentity:
			return "新增主体"
		case facts.FactAccountConfig:
			return "新增/变更配置"
		case facts.FactFilePerm:
			return "文件权限变化"
		case facts.FactServiceConfig:
			return "服务变化"
		}
		return "新增"
	}
	switch kind {
	case facts.FactPrivilege:
		return "授权消失"
	case facts.FactRoleEdge:
		return "角色关系消失"
	case facts.FactIdentity:
		return "主体消失"
	case facts.FactAccountConfig:
		return "配置消失"
	case facts.FactFilePerm:
		return "文件权限恢复"
	case facts.FactServiceConfig:
		return "服务消失"
	}
	return "消失"
}

func driftDetail(f facts.Fact) string {
	switch f.Kind {
	case facts.FactPrivilege:
		p := f.Attributes["privilege"]
		if p == "" {
			p = f.Attributes["permission"]
		}
		return fmt.Sprintf("%s @ %s", p, f.Scope)
	case facts.FactRoleEdge:
		if len(f.PermissionPath) > 0 {
			return "持有/属于 " + f.PermissionPath[0]
		}
		return f.Source
	case facts.FactAccountConfig:
		var parts []string
		for _, k := range []string{"auth_method", "name", "value", "setting", "resource", "limit", "value_in_use", "ssl_type"} {
			if v, ok := f.Attributes[k]; ok && v != "" {
				parts = append(parts, k+"="+v)
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, " ")
		}
		return f.Source
	case facts.FactFilePerm:
		return fmt.Sprintf("mode=%s other_w=%s group_w=%s", f.Attributes["mode"],
			f.Attributes["writable_by_other"], f.Attributes["writable_by_group"])
	default:
		return f.Source
	}
}

// BundleDrift 对比同一资产的两个事实包（base=旧，compare=新），输出权限语义漂移。
func BundleDrift(db *sql.DB, baseID, compareID string) (*DriftReport, error) {
	base, err := loadBundle(db, baseID)
	if err != nil {
		return nil, err
	}
	cmp, err := loadBundle(db, compareID)
	if err != nil {
		return nil, err
	}
	if base.Scope.AssetID != cmp.Scope.AssetID || base.Collector.Adapter != cmp.Collector.Adapter {
		return nil, fmt.Errorf("只能对比同一资产同一适配器的事实包（%s/%s vs %s/%s）",
			base.Scope.AssetID, base.Collector.Adapter, cmp.Scope.AssetID, cmp.Collector.Adapter)
	}
	index := func(b *facts.FactBundle) map[string]facts.Fact {
		m := map[string]facts.Fact{}
		for _, f := range b.Facts {
			if driftKinds[f.Kind] && f.Status == facts.StatusObserved {
				m[driftSignature(f)] = f
			}
		}
		return m
	}
	setA, setB := index(base), index(cmp)
	rep := &DriftReport{
		BaseID: baseID, CompareID: compareID,
		AssetID: base.Scope.AssetID, Adapter: string(base.Collector.Adapter),
		Added: []DriftItem{}, Removed: []DriftItem{},
	}
	for sig, f := range setB {
		if _, ok := setA[sig]; !ok {
			rep.AddedTotal++
			cat := driftCategory(f.Kind, true)
			if cat == "新增授权" || cat == "新增角色关系" {
				rep.Attention++
			}
			if len(rep.Added) < 500 {
				rep.Added = append(rep.Added, DriftItem{
					Kind: string(f.Kind), Source: f.Source, Subject: f.Subject,
					Category: cat, Detail: driftDetail(f),
				})
			}
		}
	}
	for sig, f := range setA {
		if _, ok := setB[sig]; !ok {
			rep.RemovedTotal++
			if len(rep.Removed) < 500 {
				rep.Removed = append(rep.Removed, DriftItem{
					Kind: string(f.Kind), Source: f.Source, Subject: f.Subject,
					Category: driftCategory(f.Kind, false), Detail: driftDetail(f),
				})
			}
		}
	}
	sortItems := func(items []DriftItem) {
		sort.Slice(items, func(i, j int) bool {
			if items[i].Category != items[j].Category {
				return items[i].Category < items[j].Category
			}
			return items[i].Subject < items[j].Subject
		})
	}
	sortItems(rep.Added)
	sortItems(rep.Removed)
	return rep, nil
}
