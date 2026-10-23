package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"medaudit/internal/license"
)

// ---------- 审计执行 ----------

func runAudit(c *client, path, asset, password, baseline, by string) (*auditRunResult, error) {
	body := map[string]any{"asset_id": asset, "password": password}
	if baseline != "" {
		body["baseline_id"] = baseline
	}
	if by != "" {
		body["created_by"] = by
	}
	var res auditRunResult
	if err := c.postJSON(path, body, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// runAuditRetry 包 ID 为秒级分辨率：同资产两次采集落在同一秒会撞「已导入」，等 2 秒重采一次。
func runAuditRetry(c *client, path, asset, password, baseline, by string) (*auditRunResult, error) {
	res, err := runAudit(c, path, asset, password, baseline, by)
	if err != nil && strings.Contains(err.Error(), "已导入") {
		time.Sleep(2 * time.Second)
		return runAudit(c, path, asset, password, baseline, by)
	}
	return res, err
}

func printAuditResult(label string, r *auditRunResult) {
	extra := ""
	if r.Transport != "" {
		extra = fmt.Sprintf(T("，传输 %s", ", transport %s"), r.Transport)
		if r.HostKeyFingerprint != "" {
			extra += T("，主机密钥 ", ", host key ") + r.HostKeyFingerprint
		}
	}
	fmt.Printf(T("%s完成%s：事实 %d / 收据 %d；评估 %d 条（FAIL %d，落库 %d）；报告 %s；事实包 %s\n", "%s done%s: %d facts / %d receipts; %d evaluated (FAIL %d, %d stored); report %s; bundle %s\n"),
		label, extra, r.Facts, r.Receipts, r.Evaluation.Total, r.Evaluation.Fail,
		r.Evaluation.FindingsStored, r.ReportID, r.BundleID)
}

func cmdAudit(args []string) error {
	if warns, err := license.Gate(time.Now()); err != nil {
		return err
	} else {
		for _, w := range warns {
			fmt.Fprintln(os.Stderr, w)
		}
	}
	p, err := parseArgs(args, []flagSpec{
		{name: "b", value: true}, {name: "e", value: true},
		{name: "f", value: true}, {name: "F"},
	})
	if err != nil {
		return err
	}
	if p.str("f") != "" {
		return cmdAuditBatch(p.str("f"), p.has("F"))
	}
	if err := p.requirePos(1, T("ma audit <资产id> [-b 基线] [-e 口令环境变量]，或 ma audit -f 清单.yaml", "ma audit <asset-id> [-b baseline] [-e password-env], or ma audit -f list.yaml")); err != nil {
		return err
	}
	assetID := p.pos[0]
	c, err := newClient()
	if err != nil {
		return err
	}
	a, err := findAsset(c, assetID)
	if err != nil {
		return err
	}
	path, label := "", ""
	switch {
	case strings.HasPrefix(a.Kind, "db-"):
		path, label = "/api/v1/audit/run", T("数据库一键审计", "Database one-click audit")
	case strings.HasPrefix(a.Kind, "os-"), strings.HasPrefix(a.Kind, "mw-"):
		path, label = "/api/v1/audit/run-remote", T("远程推送审计", "Remote push audit")
	default:
		return fmt.Errorf(T("资产 %s 的类型 %s 不支持一键审计（本地采集后用 ma bundlein 导入）", "asset %s of kind %s does not support one-click audit (collect locally and import with ma bundlein)"), assetID, a.Kind)
	}
	pw, err := auditPassword(p.str("e"), fmt.Sprintf(T("资产 %s 的口令: ", "Password for asset %s: "), assetID))
	if err != nil {
		return err
	}
	res, err := runAuditRetry(c, path, assetID, pw, p.str("b"), c.username())
	if err != nil {
		return err
	}
	printAuditResult(label, res)
	if p.has("F") && res.Evaluation.Fail > 0 {
		return &exitError{code: 2, msg: fmt.Sprintf(T("存在 %d 条 FAIL", "%d FAIL findings"), res.Evaluation.Fail)}
	}
	return nil
}

// ---------- 批量 ----------

type batchItem struct {
	Asset       string `yaml:"asset"`
	Type        string `yaml:"type"` // db | remote
	PasswordEnv string `yaml:"password_env"`
	Baseline    string `yaml:"baseline"`
}

type batchInventory struct {
	Items []batchItem `yaml:"items"`
}

func cmdAuditBatch(invPath string, failOnFail bool) error {
	raw, err := os.ReadFile(invPath)
	if err != nil {
		return err
	}
	var inventory batchInventory
	if err := yaml.Unmarshal(raw, &inventory); err != nil {
		return fmt.Errorf(T("清单解析失败: %w", "failed to parse the list file: %w"), err)
	}
	if len(inventory.Items) == 0 {
		return errors.New(T("清单为空", "the list is empty"))
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	by := c.username()
	type outcome struct {
		item batchItem
		res  *auditRunResult
		err  error
	}
	outcomes := make([]outcome, len(inventory.Items))
	var wg sync.WaitGroup
	for i, it := range inventory.Items {
		wg.Add(1)
		go func(i int, it batchItem) {
			defer wg.Done()
			path := "/api/v1/audit/run"
			if it.Type == "remote" {
				path = "/api/v1/audit/run-remote"
			}
			pw := os.Getenv(it.PasswordEnv)
			if pw == "" {
				outcomes[i] = outcome{item: it, err: fmt.Errorf(T("环境变量 %s 未设置", "environment variable %s is not set"), it.PasswordEnv)}
				return
			}
			res, err := runAuditRetry(c, path, it.Asset, pw, it.Baseline, by)
			outcomes[i] = outcome{item: it, res: res, err: err}
		}(i, it)
	}
	wg.Wait()

	failed, errored := 0, 0
	fmt.Printf("%-24s %-8s %6s %6s %s\n", T("资产", "ASSET"), T("类型", "TYPE"), T("事实", "FACTS"), "FAIL", T("报告", "REPORT"))
	for _, o := range outcomes {
		if o.err != nil {
			errored++
			fmt.Printf("%-24s %-8s %s\n", o.item.Asset, o.item.Type, T("错误：", "Error: ")+o.err.Error())
			continue
		}
		if o.res.Evaluation.Fail > 0 {
			failed++
		}
		fmt.Printf("%-24s %-8s %6d %6d %s\n", o.item.Asset, o.item.Type, o.res.Facts, o.res.Evaluation.Fail, o.res.ReportID)
	}
	fmt.Printf(T("批量完成：共 %d 项，含 FAIL %d 项，执行错误 %d 项\n", "Batch done: %d items, %d with FAIL, %d execution errors\n"), len(outcomes), failed, errored)
	if errored > 0 {
		return &exitError{code: 1, msg: fmt.Sprintf(T("%d 项执行错误", "%d items failed to execute"), errored)}
	}
	if failOnFail && failed > 0 {
		return &exitError{code: 2, msg: fmt.Sprintf(T("%d 项存在 FAIL", "%d items have FAIL"), failed)}
	}
	return nil
}

// ---------- 在线评估 ----------

func cmdEvaluate(args []string) error {
	p, err := parseArgs(args, []flagSpec{{name: "b", value: true}, {name: "F"}})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, T("ma eval <包id> [-b 基线] [-F]", "ma eval <bundle-id> [-b baseline] [-F]")); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	body := map[string]any{"bundle_id": p.pos[0]}
	if p.str("b") != "" {
		body["baseline_id"] = p.str("b")
	}
	var sum evalSummary
	if err := c.postJSON("/api/v1/evaluations", body, &sum); err != nil {
		return err
	}
	fmt.Printf(T("评估 %s：共 %d（PASS %d / FAIL %d / UNKNOWN %d / NOT_RUN %d / N/A %d），问题落库 %d\n", "Evaluation %s: %d total (PASS %d / FAIL %d / UNKNOWN %d / NOT_RUN %d / N/A %d), %d findings stored\n"),
		sum.BundleID, sum.Total, sum.Pass, sum.Fail, sum.Unknown, sum.NotRun, sum.NotApplicable, sum.FindingsStored)
	if p.has("F") && sum.Fail > 0 {
		return &exitError{code: 2, msg: fmt.Sprintf(T("存在 %d 条 FAIL", "%d FAIL findings"), sum.Fail)}
	}
	return nil
}
