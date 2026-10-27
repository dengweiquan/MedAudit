package oshpux_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"medaudit/internal/collect/oshpux"
	"medaudit/internal/facts"
	"medaudit/internal/rules"
)

// 转录夹具金值：植入集六规则精确命中、干净集全清（M21）。
func dirRunner(t *testing.T, dir string) oshpux.Runner {
	t.Helper()
	m := oshpux.MapRunner{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		m[strings.TrimSuffix(e.Name(), ".txt")] = string(raw)
	}
	return m
}

func evalHpux(t *testing.T, dir string) map[string][]rules.TechnicalResult {
	t.Helper()
	b, err := oshpux.Collect(dirRunner(t, dir), oshpux.Config{
		HospitalID: "h-test", AssetID: "os-hpux-01", CollectorVersion: "test",
		CollectorIdentity: "transcript",
	})
	if err != nil {
		t.Fatal(err)
	}
	if b.Execution != facts.ExecutionComplete {
		t.Fatalf("夹具应 COMPLETE，实际 %s（收据 %v）", b.Execution, b.Receipts)
	}
	out := map[string][]rules.TechnicalResult{}
	for _, r := range rules.DefaultRegistry().Evaluate(b, nil) {
		if strings.HasPrefix(r.RuleID, "os.hpux.") {
			out[r.RuleID] = append(out[r.RuleID], r)
		}
	}
	return out
}

func TestHpuxPlantedHits(t *testing.T) {
	res := evalHpux(t, "testdata/planted")
	want := map[string]int{
		"os.hpux.multiple_uid0":         1,
		"os.hpux.weak_password_store":   1,
		"os.hpux.inetd_risky_service":   3,
		"os.hpux.writable_service_file": 1,
		"os.hpux.setuid_unexpected":     1,
		"os.hpux.sudo_all":              1,
	}
	if len(res) != len(want) {
		t.Fatalf("应有 %d 条 hpux 规则结果，实际 %d：%v", len(want), len(res), keysOf(res))
	}
	for id, n := range want {
		rs := res[id]
		fails := 0
		for _, r := range rs {
			if r.Conclusion == facts.ConclusionFail {
				fails++
			}
			if r.Conclusion == facts.ConclusionUnknown {
				t.Fatalf("%s 不应 UNKNOWN（事实应齐备）", id)
			}
		}
		if fails != n {
			t.Fatalf("%s 应命中 %d 条 FAIL，实际 %d（结果 %v）", id, n, fails, rs)
		}
	}
}

func TestHpuxCleanPasses(t *testing.T) {
	res := evalHpux(t, "testdata/clean")
	if len(res) != 6 {
		t.Fatalf("应有 6 条 hpux 规则结果，实际 %d：%v", len(res), keysOf(res))
	}
	for id, rs := range res {
		for _, r := range rs {
			if r.Conclusion != facts.ConclusionPass {
				t.Fatalf("干净集 %s 应 PASS，实际 %s（%s）", id, r.Conclusion, r.Detail)
			}
		}
	}
}

func keysOf(m map[string][]rules.TechnicalResult) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
