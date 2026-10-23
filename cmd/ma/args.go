package main

import (
	"fmt"
	"strings"
)

// 轻量参数解析：短旗标与位置参数可交错出现（ma audit db-ora-01 -e ORA_PW）。
// 旗标规格：name 为单字母（或长名），value 表示是否带值，def 为缺省值。

type flagSpec struct {
	name  string
	value bool
	def   string
}

type parsedArgs struct {
	pos  []string
	vals map[string]string
	set  map[string]bool
}

func parseArgs(args []string, specs []flagSpec) (*parsedArgs, error) {
	byName := map[string]flagSpec{}
	p := &parsedArgs{vals: map[string]string{}, set: map[string]bool{}}
	for _, s := range specs {
		byName[s.name] = s
		if s.def != "" {
			p.vals[s.name] = s.def
		}
	}
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			p.pos = append(p.pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" && len(a) >= 2 {
			name := strings.TrimLeft(a, "-")
			// -b=value 形式
			var inline string
			hasInline := false
			if j := strings.Index(name, "="); j >= 0 {
				inline, name, hasInline = name[j+1:], name[:j], true
			}
			spec, ok := byName[name]
			if !ok {
				return nil, fmt.Errorf(T("未知旗标 -%s", "unknown flag -%s"), name)
			}
			p.set[spec.name] = true
			if !spec.value {
				p.vals[spec.name] = "true"
				i++
				continue
			}
			if hasInline {
				p.vals[spec.name] = inline
				i++
				continue
			}
			if i+1 >= len(args) {
				return nil, fmt.Errorf(T("旗标 -%s 需要一个值", "flag -%s needs a value"), name)
			}
			p.vals[spec.name] = args[i+1]
			i += 2
			continue
		}
		p.pos = append(p.pos, a)
		i++
	}
	return p, nil
}

func (p *parsedArgs) str(name string) string { return p.vals[name] }
func (p *parsedArgs) has(name string) bool   { return p.set[name] }

func (p *parsedArgs) requirePos(n int, usage string) error {
	if len(p.pos) < n {
		return fmt.Errorf("%s%s", T("用法：", "Usage: "), usage)
	}
	return nil
}
