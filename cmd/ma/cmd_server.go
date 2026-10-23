package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

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
	fmt.Printf(T("服务端 %s：%s，版本 %s\n", "Server %s: %s, version %s\n"), c.base, h.Status, h.Version)
	if u := c.username(); u != "" {
		fmt.Printf(T("当前会话用户：%s\n", "Current session user: %s\n"), u)
	}
	return nil
}

func cmdServerBackup(args []string) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	if err := p.requirePos(1, T("ma srvbak <备份文件>", "ma srvbak <backup-file>")); err != nil {
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
	fmt.Printf(T("平台库快照已下载到 %s（%d 字节，sha256 %s…）\n", "Platform database snapshot downloaded to %s (%d bytes, sha256 %s...)\n"), p.pos[0], len(raw), hex.EncodeToString(sum[:])[:16])
	fmt.Println(T("恢复方法：停服 → 用该文件替换平台库文件 → 启服（见 docs/cli-guide.md 运维节）。", "To restore: stop the service, replace the platform database file with this file, then start the service (see the operations section of docs/cli-guide.md)."))
	return nil
}

// ma srvreset：一键清场（新客户现场交接）。先在线备份到本地文件
// （备份失败即中止，绝不裸清），再调服务端清场接口；清场后全部
// 会话被吊销，本地会话文件一并清除，须以默认 admin 重新登录。
func cmdServerReset(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "o", value: true}, {name: "y"}})
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	fmt.Println(T("一键清场：将删除全部医院、资产、事实包、问题、报告、基线、规则启停与用户数据；", "One-step reset: this deletes ALL hospitals, assets, bundles, findings, reports, baselines, rule toggles and user data;"))
	fmt.Println(T("用户恢复为默认 admin（口令 admin@123，首登强制改密），全部会话吊销；许可文件与服务端配置不动。", "users are restored to the default admin (password admin@123, must change at first login) and all sessions are revoked; the license file and server configuration are untouched."))
	if !p.has("y") {
		fmt.Fprint(os.Stderr, T("确认清场？输入 WIPE 继续：", "Confirm reset: type WIPE to continue: "))
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(line) != "WIPE" {
			fmt.Println(T("已取消", "Cancelled"))
			return nil
		}
	}
	_, raw, err := c.do("GET", "/api/v1/admin/backup", nil)
	if err != nil {
		return fmt.Errorf(T("清场前备份失败，已中止: %w", "pre-reset backup failed, aborted: %w"), err)
	}
	bak := p.str("o")
	if bak == "" {
		bak = "medaudit-before-wipe-" + time.Now().Format("20060102-150405") + ".db"
	}
	if err := os.WriteFile(bak, raw, 0o600); err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	fmt.Printf(T("清场前备份已保存到 %s（%d 字节，sha256 %s…）\n", "Pre-reset backup saved to %s (%d bytes, sha256 %s...)\n"), bak, len(raw), hex.EncodeToString(sum[:])[:16])
	var out struct {
		Status       string           `json:"status"`
		Deleted      map[string]int64 `json:"deleted"`
		SiteHospital string           `json:"site_hospital"`
	}
	if err := c.postJSON("/api/v1/admin/wipe", map[string]any{}, &out); err != nil {
		return err
	}
	var total int64
	for _, n := range out.Deleted {
		total += n
	}
	clearSession()
	fmt.Printf(T("清场完成：共删除 %d 行；本地会话已清除。\n", "Reset complete: %d rows deleted; local session cleared.\n"), total)
	if out.SiteHospital != "" {
		fmt.Printf(T("本站医院 %s 已按配置重新登记。\n", "Site hospital %s re-registered from configuration.\n"), out.SiteHospital)
	}
	fmt.Println(T("请用 ma login admin 重新登录（口令 admin@123，首登强制改密）。", "Log in again with ma login admin (password admin@123, must change at first login)."))
	return nil
}

// ---------- 离线评估 ----------

// ma offeval：本地加载事实包与（可选）基线文件，以与服务端相同的规则引擎
// 求值。不访问服务端、不写平台库。
// 基线文件格式与服务端基线 spec 一致：{"ID":"...","Allows":[...]} 或 {"Allows":[...]}。
func cmdOffEval(args []string) error {
	p, err := parseArgs(args, []flagSpec{
		{name: "b", value: true}, {name: "o", value: true}, {name: "j"}, {name: "F"},
	})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, T("ma offeval <包.zip> [-b 基线.json] [-o 报告.docx] [-j] [-F]", "ma offeval <bundle.zip> [-b baseline.json] [-o report.docx] [-j] [-F]")); err != nil {
		return err
	}
	b, err := facts.ReadZip(p.pos[0])
	if err != nil {
		return fmt.Errorf(T("读取事实包失败: %w", "failed to read the bundle: %w"), err)
	}
	var baseline *rules.Baseline
	if p.str("b") != "" {
		raw, err := os.ReadFile(p.str("b"))
		if err != nil {
			return err
		}
		var bl rules.Baseline
		if err := jsonUnmarshal(raw, &bl); err != nil {
			return fmt.Errorf(T("基线解析失败: %w", "failed to parse the baseline: %w"), err)
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
			return fmt.Errorf(T("生成 Word 失败: %w", "failed to generate the Word report: %w"), err)
		}
		if err := os.WriteFile(p.str("o"), raw, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, T("离线 Word 报告已写入 %s\n", "Offline Word report written to %s\n"), p.str("o"))
	}
	if p.has("j") {
		if err := printJSON(results); err != nil {
			return err
		}
	} else {
		fmt.Printf(T("事实包 %s（%s / %s，执行 %s）：共 %d 条 — PASS %d、FAIL %d、UNKNOWN %d、NOT_RUN %d、NOT_APPLICABLE %d\n", "Bundle %s (%s / %s, execution %s): %d results — PASS %d, FAIL %d, UNKNOWN %d, NOT_RUN %d, NOT_APPLICABLE %d\n"),
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
		return &exitError{code: 2, msg: fmt.Sprintf(T("存在 %d 条 FAIL", "%d FAIL findings"), counts[facts.ConclusionFail])}
	}
	return nil
}
