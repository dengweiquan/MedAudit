package platform

import (
	"encoding/json"
	"fmt"

	"medaudit/internal/apiaudit"
	"medaudit/internal/facts"
	"medaudit/internal/rules"
)

// API 审计报告的合规判定（M4-4，医疗-12）：
//   检查项（apiaudit 探针）→ 报告 → 持久化 → 本函数（合规报告）→ Web（合规端点）。
// 绑定是判定有效的硬前提：报告须为 apiaudit/v1 格式且绑定医院与资产，
// 服务端还须核实资产存在且归属该医院（assetVerified 由调用方用库查询确认）。
// 任一条件不满足时不做评估、不纳入通过，条款状态为 unknown 并附原因：
// 历史报告（无 schema 版本、无绑定）尤其不得因旧检查全过而被算作合规通过。
// 统计一律由 checks 重算，不信任报告内 Summary（客户端可谎报）。

var apiComplianceRuleIDs = []string{
	"api.anon_protected_access",
	"api.user_admin_access",
	"api.cross_owner_access",
	"api.invalidated_session_replay",
}

// APIComplianceResult 医疗-12 条款判定（供服务端点与 Web 展示）。
type APIComplianceResult struct {
	ReportID      string           `json:"report_id"`
	Target        string           `json:"target"`
	SchemaVersion string           `json:"schema_version"`
	HospitalID    string           `json:"hospital_id,omitempty"`
	AssetID       string           `json:"asset_id,omitempty"`
	Bound         bool             `json:"bound"`
	Clause        ComplianceClause `json:"clause"`
	Controls      []string         `json:"controls"`
	Summary       map[string]int   `json:"summary"`
	Note          string           `json:"note,omitempty"`
}

// CountAPIAuditSummary 由 checks 重算统计（服务端存档与合规判定共用，
// 不信任客户端或存档报告内的 Summary）。
func CountAPIAuditSummary(checks []apiaudit.Check) map[string]int {
	out := map[string]int{"PASS": 0, "FAIL": 0, "UNKNOWN": 0, "NOT_RUN": 0}
	for _, c := range checks {
		out[string(c.Conclusion)]++
	}
	return out
}

// APICompliance 计算医疗-12 条款判定。assetVerified 为 false 时（绑定资产
// 未经库核实，如资产已删或归属不符）同样不评估，只返回 unknown。
func APICompliance(reportJSON []byte, assetVerified bool) (*APIComplianceResult, error) {
	var rep apiaudit.Report
	if err := json.Unmarshal(reportJSON, &rep); err != nil {
		return nil, fmt.Errorf("解析 API 审计报告失败: %w", err)
	}
	res := &APIComplianceResult{
		ReportID:      rep.ReportID,
		Target:        rep.Target,
		SchemaVersion: rep.SchemaVersion,
		HospitalID:    rep.HospitalID,
		AssetID:       rep.AssetID,
		Summary:       CountAPIAuditSummary(rep.Checks),
	}
	clause := ComplianceClause{ID: "医疗-12", Group: "API 安全",
		Title: "应用程序接口访问控制与鉴权，防止越权访问"}
	if fws, _ := rules.LoadFrameworks(""); len(fws) > 0 {
		for _, fw := range fws {
			if fw.ID != "medical-draft" {
				continue
			}
			for _, c := range fw.Controls {
				if c.ID == "医疗-12" {
					clause.Ref, clause.Group, clause.Title = c.Ref, c.Group, c.Title
				}
			}
		}
	}
	unknownClause := func(note string) *APIComplianceResult {
		clause.Status = "unknown"
		for _, id := range apiComplianceRuleIDs {
			clause.Rules = append(clause.Rules, ComplianceRule{
				RuleID: id, Name: ruleName(id), Outcome: outUnknown,
			})
		}
		res.Clause, res.Note = clause, note
		return res
	}
	switch {
	case rep.SchemaVersion != apiaudit.SchemaVersion:
		return unknownClause("报告为老格式（无 schema 版本），无法可靠绑定目标，不纳入合规通过；请用新版采集器重跑"), nil
	case rep.HospitalID == "" || rep.AssetID == "":
		return unknownClause("报告未绑定医院/资产，无法归属到具体对象，不纳入合规通过；请在 apicheck 配置中填写 hospital_id/asset_id 后重跑"), nil
	case rep.Target == "" || rep.ReportID == "":
		return unknownClause("报告缺少目标或运行标识，无法可靠绑定，不纳入合规通过"), nil
	case !assetVerified:
		return unknownClause("绑定资产未经核实（资产不存在或不归属该医院），不纳入合规通过"), nil
	}
	res.Bound = true
	factList := apiaudit.ToFacts(&rep)
	b := &facts.FactBundle{
		Collector: facts.CollectorInfo{Name: "apiaudit", Adapter: facts.TargetAPI},
		Scope: facts.Scope{HospitalID: rep.HospitalID, AssetID: rep.AssetID,
			TargetType: facts.TargetAPI},
		Identities: facts.Identities{CollectorIdentity: "apiaudit", TargetIdentity: rep.Target},
		Facts:      factList,
	}
	seen := map[string]bool{}
	for _, f := range factList {
		if f.Source == "api.control" {
			seen[f.Attributes["control"]] = true
		}
	}
	for k := range seen {
		res.Controls = append(res.Controls, k)
	}
	results := rules.DefaultRegistry().Evaluate(b, &rules.Baseline{})
	byID := map[string][]rules.TechnicalResult{}
	for _, r := range results {
		byID[r.RuleID] = append(byID[r.RuleID], r)
	}
	var hasFail, hasUnknown, hasPass bool
	for _, id := range apiComplianceRuleIDs {
		rs := byID[id]
		o := ComplianceRule{RuleID: id, Name: ruleName(id)}
		switch {
		case len(rs) == 0:
			o.Outcome = outUnknown
		default:
			fail := 0
			unknown := false
			pass := false
			for _, r := range rs {
				switch r.Conclusion {
				case facts.ConclusionFail:
					fail++
				case facts.ConclusionUnknown, facts.ConclusionNotRun:
					unknown = true
				case facts.ConclusionPass:
					pass = true
				}
			}
			switch {
			case fail > 0:
				o.Outcome, o.Fails = outFail, fail
			case unknown:
				o.Outcome = outUnknown
			case pass:
				o.Outcome = outPass
			default: // NOT_APPLICABLE
				o.Outcome = outNA
			}
		}
		switch o.Outcome {
		case outFail:
			hasFail = true
		case outUnknown:
			hasUnknown = true
		case outPass:
			hasPass = true
		}
		clause.Rules = append(clause.Rules, o)
	}
	switch {
	case hasFail:
		clause.Status = "fail"
	case hasUnknown:
		clause.Status = "unknown"
	case hasPass:
		clause.Status = "pass"
	default:
		clause.Status = "na"
	}
	res.Clause = clause
	return res, nil
}
