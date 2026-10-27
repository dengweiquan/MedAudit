package rules

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

const rulesetsDir = "../../rulesets"

// TestRulesetsInSync 保证 rulesets/*.yaml 与内置规则逐字一致、一一对应。
// 规则文本或版本变更后执行 go test ./internal/rules -run Rulesets -update 重新生成。
func TestRulesetsInSync(t *testing.T) {
	specs := DefaultRegistry().Rules()
	want := map[string]string{}
	for _, s := range specs {
		out := MetadataYAML(s)
		var parsed map[string]any
		if err := yaml.Unmarshal([]byte(out), &parsed); err != nil || parsed["id"] != s.ID {
			t.Fatalf("%s 生成的 YAML 无法解析: %v", s.ID, err)
		}
		want[s.ID+".yaml"] = out
	}
	if *updateGolden {
		old, _ := filepath.Glob(filepath.Join(rulesetsDir, "*.yaml"))
		for _, p := range old {
			if _, ok := want[filepath.Base(p)]; !ok {
				os.Remove(p)
			}
		}
		for name, content := range want {
			if err := os.WriteFile(filepath.Join(rulesetsDir, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	have, _ := filepath.Glob(filepath.Join(rulesetsDir, "*.yaml"))
	seen := map[string]bool{}
	for _, p := range have {
		name := filepath.Base(p)
		seen[name] = true
		exp, ok := want[name]
		if !ok {
			t.Errorf("%s 没有对应的内置规则（请删除或 -update）", name)
			continue
		}
		got, _ := os.ReadFile(p)
		if string(got) != exp {
			t.Errorf("%s 与内置规则不一致（请 -update 重新生成）", name)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("缺少 rulesets/%s（请 -update 生成）", name)
		}
	}
}

// TestComplianceMappingComplete 每条内置规则都须映射到至少一个条款，映射不得指向不存在的规则或条款。
func TestComplianceMappingComplete(t *testing.T) {
	known := map[string]bool{}
	for _, s := range DefaultRegistry().Rules() {
		known[s.ID] = true
		if len(ControlsFor(s.ID)) == 0 {
			t.Errorf("%s 未映射合规条款", s.ID)
		}
	}
	for id, keys := range ruleControls {
		if !known[id] {
			t.Errorf("条款映射引用了不存在的规则 %s", id)
		}
		for _, k := range keys {
			if _, ok := controls[k]; !ok {
				t.Errorf("%s 引用了不存在的条款 %s", id, k)
			}
		}
	}
}
