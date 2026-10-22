package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"medaudit/internal/facts"
	"medaudit/internal/platform"
	"medaudit/internal/rules"
)

// ---------- 服务端 ----------

func cmdServerStatus(args []string) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	var h struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := c.getJSON("/api/v1/health", &h); err != nil {
		return err
	}
	fmt.Printf("服务端 %s：%s，版本 %s\n", c.base, h.Status, h.Version)
	if u := c.username(); u != "" {
		fmt.Printf("当前会话用户：%s\n", u)
	}
	return nil
}

func cmdServerBackup(args []string) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	if err := p.requirePos(1, "masrvbak <备份文件>"); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	_, raw, err := c.do("GET", "/api/v1/admin/backup", nil)
	if err != nil {
		return err
	}
	if err := os.WriteFile(p.pos[0], raw, 0o600); err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	fmt.Printf("平台库快照已下载到 %s（%d 字节，sha256 %s…）\n", p.pos[0], len(raw), hex.EncodeToString(sum[:])[:16])
	fmt.Println("恢复方法：停服 → 用该文件替换平台库文件 → 启服（见 docs/cli-guide.md 运维节）。")
	return nil
}

// ---------- 离线评估 ----------

// maoffeval：本地加载事实包与（可选）基线文件，以与服务端相同的规则引擎
// 求值。不访问服务端、不写平台库。
// 基线文件格式与服务端基线 spec 一致：{"ID":"...","Allows":[...]} 或 {"Allows":[...]}。
func cmdOffEval(args []string) error {
	p, err := parseArgs(args, []flagSpec{
		{name: "b", value: true}, {name: "o", value: true}, {name: "j"}, {name: "F"},
	})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, "maoffeval <包.zip> [-b 基线.json] [-o 报告.docx] [-j] [-F]"); err != nil {
		return err
	}
	b, err := facts.ReadZip(p.pos[0])
	if err != nil {
		return fmt.Errorf("读取事实包失败: %w", err)
	}
	var baseline *rules.Baseline
	if p.str("b") != "" {
		raw, err := os.ReadFile(p.str("b"))
		if err != nil {
			return err
		}
		var bl rules.Baseline
		if err := jsonUnmarshal(raw, &bl); err != nil {
			return fmt.Errorf("基线解析失败: %w", err)
		}
		baseline = &bl
	}
	results := rules.DefaultRegistry().Evaluate(b, baseline)

	counts := map[facts.Conclusion]int{}
	for _, r := range results {
		counts[r.Conclusion]++
	}
	if p.str("o") != "" {
		raw, err := platform.RenderEvalDocx(b, results)
		if err != nil {
			return fmt.Errorf("生成 Word 失败: %w", err)
		}
		if err := os.WriteFile(p.str("o"), raw, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "离线 Word 报告已写入 %s\n", p.str("o"))
	}
	if p.has("j") {
		if err := printJSON(results); err != nil {
			return err
		}
	} else {
		fmt.Printf("事实包 %s（%s / %s，执行 %s）：共 %d 条 — PASS %d、FAIL %d、UNKNOWN %d、NOT_RUN %d、NOT_APPLICABLE %d\n",
			b.BundleID, b.Scope.HospitalID, b.Scope.AssetID, b.Execution, len(results),
			counts[facts.ConclusionPass], counts[facts.ConclusionFail], counts[facts.ConclusionUnknown],
			counts[facts.ConclusionNotRun], counts[facts.ConclusionNotApplicable])
		for _, r := range results {
			if r.Conclusion == facts.ConclusionFail {
				fmt.Printf("  [FAIL] %s · %s — %s\n", r.RuleID, r.Subject, string(r.Detail))
			}
		}
	}
	if p.has("F") && counts[facts.ConclusionFail] > 0 {
		return &exitError{code: 2, msg: fmt.Sprintf("存在 %d 条 FAIL", counts[facts.ConclusionFail])}
	}
	return nil
}
