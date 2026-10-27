package rules

import (
	"strings"
)

// MetadataYAML 渲染规则元数据 YAML（rulesets/<id>.yaml 的唯一来源）。
// 内置 Go 规则是运行时真相，rulesets 目录由此函数生成，不手改。
func MetadataYAML(s RuleSpec) string {
	var b strings.Builder
	b.WriteString("# MedAudit 内置规则元数据（由 internal/rules 生成，请勿手改）\n")
	b.WriteString("id: " + s.ID + "\n")
	b.WriteString("version: \"" + s.Version + "\"\n")
	b.WriteString("name: " + s.Name + "\n")
	b.WriteString("target: " + string(s.Target) + "\n")
	b.WriteString("risk: " + string(s.Risk) + "\n")
	writeBlock(&b, "description", s.Description)
	req := make([]string, len(s.Requires))
	for i, k := range s.Requires {
		req[i] = string(k)
	}
	b.WriteString("requires: [" + strings.Join(req, ", ") + "]\n")
	writeBlock(&b, "remediation", s.Remediation)
	return b.String()
}

func writeBlock(b *strings.Builder, key, text string) {
	b.WriteString(key + ": |\n")
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		b.WriteString("  " + line + "\n")
	}
}
