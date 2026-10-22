package platform

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"medaudit/internal/facts"
	"medaudit/internal/rules"
)

// GenerateReport 生成不可变报告快照：范围 + 评估汇总 + 问题清单 + 版本。
func GenerateReport(db *sql.DB, hospitalID, planID, bundleID, createdBy string) (string, error) {
	var bundleRaw, adapter, execution, assetID, importedAt string
	err := db.QueryRow(`SELECT bundle, adapter, execution, asset_id, imported_at FROM fact_bundles WHERE id = ?`, bundleID).
		Scan(&bundleRaw, &adapter, &execution, &assetID, &importedAt)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("事实包 %s 不存在", bundleID)
	}
	if err != nil {
		return "", err
	}
	findings, err := ListFindings(db, bundleID)
	if err != nil {
		return "", err
	}
	// 统计口径：可判定覆盖 = (PASS+FAIL)/适用检查项；NOT_RUN 与 UNKNOWN 留在分母。
	// 此处 findings 只存非 PASS/非 NOT_APPLICABLE，PASS 数从评估时另计；报告记录口径说明。
	summary := map[string]any{}
	for _, f := range findings {
		summary[f.Conclusion] = 0
	}
	for _, f := range findings {
		summary[f.Conclusion] = summary[f.Conclusion].(int) + 1
	}
	coverage := computeCoverage(bundleRaw)

	// M18：报告展示元数据（医院/对象显示名），渲染层不再直出内部 ID。
	meta := map[string]any{"asset_id": assetID, "bundle_imported_at": importedAt}
	var hospName string
	if err := db.QueryRow(`SELECT name FROM hospitals WHERE id = ?`, hospitalID).Scan(&hospName); err == nil {
		meta["hospital_name"] = hospName
	}
	var assetName, assetKind string
	if err := db.QueryRow(`SELECT name, kind FROM assets WHERE id = ?`, assetID).Scan(&assetName, &assetKind); err == nil {
		meta["asset_name"] = assetName
		meta["asset_kind"] = assetKind
	}

	snapshot := map[string]any{
		"hospital_id":        hospitalID,
		"plan_id":            planID,
		"bundle_id":          bundleID,
		"adapter":            adapter,
		"execution":          execution,
		"generated_at":       time.Now().UTC().Format(time.RFC3339),
		"conclusion_summary": summary,
		"coverage":           coverage,
		"coverage_note":      "覆盖率见 coverage：资产/服务关联/账号/可判定四路；可判定率=(PASS+FAIL)/(结论总数-NOT_APPLICABLE)；技术口径（无基线）重算，findings 为落库口径（含基线时点可能不同）",
		"findings":           findings,
		"report_meta":        meta,
	}
	// M10 深化章节：关联路径与权限漂移（生成时点快照口径；无数据整段缺省，不写空章节）。
	if sec := correlationSection(db, hospitalID, bundleID); sec != nil {
		snapshot["privilege_paths"] = sec
	}
	if sec := driftSection(db, bundleID); sec != nil {
		snapshot["drift"] = sec
	}
	if sec := remediationSection(bundleRaw, findings); sec != nil {
		snapshot["remediation"] = sec
	}
	snapJSON, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	reportID := fmt.Sprintf("report-%s-%d", bundleID, time.Now().Unix())
	_, err = db.Exec(
		`INSERT INTO reports (id, hospital_id, plan_id, snapshot, created_by) VALUES (?, ?, ?, ?, ?)`,
		reportID, hospitalID, planID, string(snapJSON), createdBy)
	if err != nil {
		return "", err
	}
	return reportID, nil
}

// computeCoverage 从事实包本体与技术口径（无基线）重评估计算覆盖率四路指标。
// 任一解析失败返回带 error 的 map，绝不静默给 0 值装作测过。
func computeCoverage(bundleRaw string) map[string]any {
	var b facts.FactBundle
	if err := json.Unmarshal([]byte(bundleRaw), &b); err != nil {
		return map[string]any{"error": "事实包解析失败: " + err.Error()}
	}

	kindCounts := map[string]int{}
	accounts := map[string]bool{}
	deniedFacts := 0
	services, processes, databases := 0, 0, 0
	for _, f := range b.Facts {
		kindCounts[string(f.Kind)]++
		if f.Status == facts.StatusPermissionDenied {
			deniedFacts++
		}
		switch f.Kind {
		case facts.FactIdentity:
			// 采集会话身份不算被核查账号。
			if !strings.HasSuffix(f.Source, ".session") {
				accounts[f.Subject] = true
			}
			if strings.Contains(f.Source, ".databases") {
				databases++
			}
		case facts.FactServiceConfig:
			services++
		case facts.FactProcess:
			processes++
		}
	}

	// 可判定：技术口径重评估（无基线），统计全部结论。
	results := rules.DefaultRegistry().Evaluate(&b, nil)
	concl := map[string]int{}
	for _, r := range results {
		concl[string(r.Conclusion)]++
	}
	total := len(results)
	applicable := total - concl[string(facts.ConclusionNotApplicable)]
	determinable := concl[string(facts.ConclusionPass)] + concl[string(facts.ConclusionFail)]
	var rate any
	if applicable > 0 {
		rate = float64(determinable) / float64(applicable)
	}

	deniedReceipts := 0
	for _, rc := range b.Receipts {
		if rc.Status == "denied" {
			deniedReceipts++
		}
	}

	return map[string]any{
		"asset": map[string]any{
			"asset_id": b.Scope.AssetID, "adapter": string(b.Collector.Adapter),
			"target_type": string(b.Scope.TargetType), "target_version": b.Scope.TargetVersion,
		},
		"linkage": map[string]any{
			"service_config_facts": services,
			"process_facts":        processes,
			"database_facts":       databases,
		},
		"accounts": map[string]any{
			"distinct_identity_subjects": len(accounts),
			"role_edges":                 kindCounts[string(facts.FactRoleEdge)],
			"privilege_facts":            kindCounts[string(facts.FactPrivilege)],
		},
		"evidence": map[string]any{
			"facts_total": len(b.Facts), "by_kind": kindCounts,
			"receipts_total": len(b.Receipts), "receipts_denied": deniedReceipts,
			"permission_denied_facts": deniedFacts,
		},
		"determinability": map[string]any{
			"rule_results_total": total,
			"by_conclusion":      concl,
			"applicable":         applicable,
			"determinable":       determinable,
			"determinable_rate":  rate,
			"basis":              "技术口径重评估（无基线）",
		},
	}
}

// correlationSection 取同医院最新一份「包含本事实包」的关联报告，摘录为报告章节。
// 路径清单上限 50 条（path_count 为全量计数）；无关联报告时返回 nil。
func correlationSection(db *sql.DB, hospitalID, bundleID string) map[string]any {
	rows, err := db.Query(
		`SELECT report_id FROM correlation_reports WHERE hospital_id = ? ORDER BY created_at DESC LIMIT 20`, hospitalID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var candidateIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil
		}
		candidateIDs = append(candidateIDs, id)
	}
	rows.Close()
	for _, id := range candidateIDs {
		detail, err := GetCorrelation(db, id)
		if err != nil {
			continue
		}
		contains := false
		for _, b := range detail.BundleIDs {
			if b == bundleID {
				contains = true
				break
			}
		}
		if !contains {
			continue
		}
		paths := make([]map[string]any, 0, len(detail.Result.Paths))
		for i, p := range detail.Result.Paths {
			if i >= 50 {
				break
			}
			chain := p.Source
			for _, h := range p.Hops {
				chain += " --" + h.Action + "--> " + h.To
			}
			if len(p.Hops) == 0 {
				chain += " --> " + p.Target
			}
			paths = append(paths, map[string]any{
				"source": p.Source, "target": p.Target, "risk": p.Risk, "chain": chain,
			})
		}
		return map[string]any{
			"correlation_report_id": detail.ReportID,
			"generated_at":          detail.CreatedAt,
			"bundle_ids":            detail.BundleIDs,
			"nodes":                 detail.Result.Nodes,
			"edges":                 detail.Result.Edges,
			"path_count":            detail.PathCount,
			"paths":                 paths,
			"note":                  "快照口径：报告生成时点同医院最新一份包含本事实包的关联报告；路径清单上限 50 条，path_count 为全量。",
		}
	}
	return nil
}

// driftSection 同资产同适配器的上一事实包漂移摘要；无上一包返回 nil。
// 清单各截断 100 条，计数为全量（BundleDrift 口径）。
func driftSection(db *sql.DB, bundleID string) map[string]any {
	var prevID string
	err := db.QueryRow(
		`SELECT id FROM fact_bundles
		  WHERE asset_id = (SELECT asset_id FROM fact_bundles WHERE id = ?)
		    AND adapter = (SELECT adapter FROM fact_bundles WHERE id = ?)
		    AND imported_at < (SELECT imported_at FROM fact_bundles WHERE id = ?)
		  ORDER BY imported_at DESC LIMIT 1`, bundleID, bundleID, bundleID).Scan(&prevID)
	if err != nil {
		return nil
	}
	rep, err := BundleDrift(db, prevID, bundleID)
	if err != nil {
		return nil
	}
	capItems := func(items []DriftItem) []DriftItem {
		if len(items) > 100 {
			return items[:100]
		}
		return items
	}
	return map[string]any{
		"base_id":       rep.BaseID,
		"added_total":   rep.AddedTotal,
		"removed_total": rep.RemovedTotal,
		"attention":     rep.Attention,
		"added":         capItems(rep.Added),
		"removed":       capItems(rep.Removed),
		"note":          "与同资产上一事实包的权限语义漂移（BundleDrift 口径）；清单各上限 100 条，计数为全量。",
	}
}
