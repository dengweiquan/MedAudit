package main

import (
	"encoding/csv"
	"fmt"
	"net/url"
	"os"
	"sort"
)

// ---------- 问题 ----------

func cmdFindings(args []string) error {
	p, err := parseArgs(args, []flagSpec{
		{name: "c", value: true}, {name: "r", value: true},
		{name: "j"}, {name: "o", value: true},
	})
	if err != nil {
		return err
	}
	if err := p.requirePos(1, T("ma find <包id> [-c 结论] [-r 规则] [-j] [-o 清单.csv]", "ma find <bundle-id> [-c conclusion] [-r rule] [-j] [-o list.csv]")); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var rows []findingRow
	if err := c.getJSON("/api/v1/findings?bundle_id="+url.QueryEscape(p.pos[0])+"&limit=10000", &rows); err != nil {
		return err
	}
	var out []findingRow
	for _, r := range rows {
		if p.str("c") != "" && r.Conclusion != p.str("c") {
			continue
		}
		if p.str("r") != "" && r.RuleID != p.str("r") {
			continue
		}
		out = append(out, r)
	}
	if p.str("o") != "" {
		if err := writeFindingsCSV(p.str("o"), out); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, T("CSV 已写入 %s（%d 行）\n", "CSV written to %s (%d rows)\n"), p.str("o"), len(out))
	}
	if p.has("j") {
		return printJSON(out)
	}
	for _, r := range out {
		fmt.Printf("[%s] %s · %s — %s\n", r.Conclusion, r.RuleID, r.Subject, r.detailText())
	}
	fmt.Printf(T("共 %d 条\n", "%d in total\n"), len(out))
	return nil
}

func writeFindingsCSV(path string, rows []findingRow) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, _ = f.Write([]byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM：Excel 中文不乱码
	w := csv.NewWriter(f)
	_ = w.Write([]string{"finding_id", "rule_id", "rule_version", "subject", "conclusion", "review_status", "detail", "created_at"})
	for _, r := range rows {
		_ = w.Write([]string{fmt.Sprint(r.ID), r.RuleID, r.RuleVersion, r.Subject, r.Conclusion, r.ReviewStatus, r.detailText(), r.CreatedAt})
	}
	w.Flush()
	return w.Error()
}

// ---------- 关联 ----------

func cmdCorrelate(args []string) error {
	p, err := parseArgs(args, nil)
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	ids := p.pos
	if len(ids) == 0 {
		// 缺省：当前医院各资产的最新包
		hosp, err := c.contextHospital("")
		if err != nil {
			return err
		}
		bundles, err := fetchBundles(c)
		if err != nil {
			return err
		}
		latest := map[string]bundleSummary{}
		for _, b := range bundles {
			if b.HospitalID != hosp {
				continue
			}
			if cur, ok := latest[b.AssetID]; !ok || b.ImportedAt > cur.ImportedAt {
				latest[b.AssetID] = b
			}
		}
		assets := make([]string, 0, len(latest))
		for a := range latest {
			assets = append(assets, a)
		}
		sort.Strings(assets)
		for _, a := range assets {
			ids = append(ids, latest[a].ID)
		}
		if len(ids) < 2 || len(ids) > 12 {
			return fmt.Errorf(T("自动选取得到 %d 个包（需 2–12）：请显式给包 ID", "auto-selection produced %d bundles (need 2-12): give bundle IDs explicitly"), len(ids))
		}
		fmt.Fprintf(os.Stderr, T("自动选取 %s 各资产最新包共 %d 个\n", "Auto-selected the latest bundle of each asset in %s: %d bundles\n"), hosp, len(ids))
	}
	var detail struct {
		ReportID  string `json:"report_id"`
		PathCount int    `json:"path_count"`
		Result    struct {
			Nodes int `json:"nodes"`
			Edges int `json:"edges"`
			Paths []struct {
				Source string `json:"source"`
				Target string `json:"target"`
				Risk   string `json:"risk"`
				Hops   []struct {
					Action string `json:"action"`
					To     string `json:"to"`
				} `json:"hops"`
			} `json:"paths"`
		} `json:"result"`
	}
	if err := c.postJSON("/api/v1/correlations", map[string]any{"bundle_ids": ids, "created_by": c.username()}, &detail); err != nil {
		return err
	}
	fmt.Printf(T("关联报告 %s：图 %d 节点/%d 边，提权路径 %d 条\n", "Correlation report %s: graph %d nodes/%d edges, %d privilege paths\n"), detail.ReportID, detail.Result.Nodes, detail.Result.Edges, detail.PathCount)
	for _, pth := range detail.Result.Paths {
		chain := pth.Source
		for _, h := range pth.Hops {
			chain += " --" + h.Action + "--> " + h.To
		}
		fmt.Printf("  [%s] %s\n", pth.Risk, chain)
	}
	return nil
}

// ---------- 汇总 ----------

func cmdSummary(args []string) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	var rows []hospitalSummary
	if err := c.getJSON("/api/v1/summary/hospitals", &rows); err != nil {
		return err
	}
	want := ""
	if s, err := loadSession(); err == nil && s.Hospital != "" {
		want = s.Hospital
	} else {
		want = c.siteHospitalID()
	}
	fmt.Printf("%-16s %5s %5s %7s %7s %7s %s\n", T("医院", "HOSPITAL"), T("资产", "ASSETS"), T("事实包", "BUNDLES"), "FAIL", T("未闭环", "OPEN"), "UNKNOWN", T("关联路径", "CORR PATHS"))
	for _, h := range rows {
		if want != "" && h.HospitalID != want {
			continue
		}
		fmt.Printf("%-16s %5d %5d %7d %7d %7d %d\n", h.HospitalID, h.Assets, h.Bundles, h.FailTotal, h.FailOpen, h.UnknownTotal, h.CorrPaths)
	}
	return nil
}
