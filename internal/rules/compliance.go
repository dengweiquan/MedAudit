package rules

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"gopkg.in/yaml.v3"
)

// 合规条款框架：每个框架（标准）列出条款及对应的平台规则，数据在
// compliance/*.yaml（随程序内嵌）。站点可在目录中放同格式文件新增或按 id 覆盖。
// 报告据此逐条给出「满足 / 不满足 / 无法判定 / 不涉及 / 本平台未检查」。

//go:embed compliance/*.yaml
var complianceFS embed.FS

// Framework 一个合规标准。
type Framework struct {
	ID       string             `yaml:"id" json:"id"`
	Name     string             `yaml:"name" json:"name"`
	Short    string             `yaml:"short" json:"short"`
	Status   string             `yaml:"status" json:"status"` // verified | draft
	Controls []FrameworkControl `yaml:"controls" json:"controls"`
	Source   string             `yaml:"-" json:"source"` // builtin | site
}

// FrameworkControl 一个条款。
type FrameworkControl struct {
	ID    string   `yaml:"id" json:"id"`
	Ref   string   `yaml:"ref" json:"ref"` // 标准原文条款号（草稿框架待填）
	Group string   `yaml:"group" json:"group"`
	Title string   `yaml:"title" json:"title"`
	Rules []string `yaml:"rules" json:"rules"`
}

// Control 规则所对应的一个条款（规则页、规则元数据用）。
type Control struct {
	ID    string `json:"id"`
	Group string `json:"group"`
	Title string `json:"title"`
}

// DefaultFrameworkID 规则元数据与规则页标注所用的主框架。
const DefaultFrameworkID = "djbh2-l3"

// ComplianceFramework 主框架名称。
var ComplianceFramework = mustBuiltin(DefaultFrameworkID).Name

func parseFramework(data []byte, source string) (*Framework, error) {
	var f Framework
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	if f.ID == "" || f.Name == "" || len(f.Controls) == 0 {
		return nil, fmt.Errorf("框架缺少 id/name/controls")
	}
	if f.Status != "verified" {
		f.Status = "draft"
	}
	if f.Short == "" {
		f.Short = f.Name
	}
	for i, c := range f.Controls {
		if c.ID == "" || c.Title == "" {
			return nil, fmt.Errorf("第 %d 个条款缺少 id/title", i+1)
		}
	}
	f.Source = source
	return &f, nil
}

var (
	builtinOnce sync.Once
	builtinFws  []Framework
)

// BuiltinFrameworks 随程序内嵌的框架（按 id 排序）。
func BuiltinFrameworks() []Framework {
	builtinOnce.Do(func() {
		entries, _ := complianceFS.ReadDir("compliance")
		for _, e := range entries {
			data, err := complianceFS.ReadFile("compliance/" + e.Name())
			if err != nil {
				panic(err)
			}
			f, err := parseFramework(data, "builtin")
			if err != nil {
				panic(fmt.Sprintf("内置合规框架 %s: %v", e.Name(), err))
			}
			builtinFws = append(builtinFws, *f)
		}
		sort.Slice(builtinFws, func(i, j int) bool { return builtinFws[i].ID < builtinFws[j].ID })
	})
	return builtinFws
}

func mustBuiltin(id string) Framework {
	for _, f := range BuiltinFrameworks() {
		if f.ID == id {
			return f
		}
	}
	panic("缺少内置合规框架 " + id)
}

// LoadFrameworks 内置框架 + siteDir/*.yaml（同 id 覆盖内置）。站点文件解析失败的跳过并返回说明。
func LoadFrameworks(siteDir string) ([]Framework, []string) {
	byID := map[string]Framework{}
	var order []string
	for _, f := range BuiltinFrameworks() {
		byID[f.ID] = f
		order = append(order, f.ID)
	}
	var errs []string
	if siteDir != "" {
		files, _ := filepath.Glob(filepath.Join(siteDir, "*.yaml"))
		for _, p := range files {
			data, err := os.ReadFile(p)
			if err != nil {
				errs = append(errs, p+": "+err.Error())
				continue
			}
			f, err := parseFramework(data, "site")
			if err != nil {
				errs = append(errs, p+": "+err.Error())
				continue
			}
			if _, ok := byID[f.ID]; !ok {
				order = append(order, f.ID)
			}
			byID[f.ID] = *f
		}
	}
	out := make([]Framework, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out, errs
}

// ControlsFor 返回规则在主框架（等保 2.0 三级）中对应的条款，按框架顺序。
func ControlsFor(ruleID string) []Control {
	var out []Control
	for _, c := range mustBuiltin(DefaultFrameworkID).Controls {
		for _, r := range c.Rules {
			if r == ruleID {
				out = append(out, Control{ID: c.ID, Group: c.Group, Title: c.Title})
				break
			}
		}
	}
	return out
}
