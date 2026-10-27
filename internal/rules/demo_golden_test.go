package rules

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"medaudit/internal/facts"
)

var updateGolden = flag.Bool("update", false, "重写 testdata/golden 下的快照")

// TestDemoBundlesGolden 用 pilot/demo-data 的真实采集事实包做端到端快照：
// 规则或引擎一改，结论变化在快照 diff 里一目了然。
// 规则有意变更后执行 go test ./internal/rules -run Golden -update 刷新快照。
func TestDemoBundlesGolden(t *testing.T) {
	zips, err := filepath.Glob("../../pilot/demo-data/*.zip")
	if err != nil || len(zips) == 0 {
		t.Fatalf("未找到演示事实包: %v", err)
	}
	reg := DefaultRegistry()
	for _, z := range zips {
		name := strings.TrimSuffix(filepath.Base(z), ".zip")
		t.Run(name, func(t *testing.T) {
			b, err := facts.ReadZip(z)
			if err != nil {
				t.Fatalf("读取 %s: %v", z, err)
			}
			got := summarize(reg.Evaluate(b, &Baseline{}))
			path := filepath.Join("testdata", "golden", name+".golden")
			if *updateGolden {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("缺少快照 %s（首次请加 -update 生成）: %v", path, err)
			}
			if got != string(want) {
				t.Errorf("%s 评估结论与快照不一致；若属有意变更请加 -update 刷新。\n--- 期望\n%s\n--- 实际\n%s", name, want, got)
			}
		})
	}
}

// summarize 只取稳定字段（规则、结论、风险、主体）并排序，避免详情文案抖动。
func summarize(rs []TechnicalResult) string {
	lines := make([]string, 0, len(rs))
	for _, r := range rs {
		if r.Conclusion == facts.ConclusionNotApplicable {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s\t%s", r.RuleID, r.Conclusion, r.Risk, r.Subject))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}
