// Package rules 提供纯规则评估引擎。
// 评估过程不发请求、不运行命令、不修改被测系统；输入 FactBundle + Baseline + RuleSet，
// 输出带证据引用的技术结论。规则判定用编译期注册的检查函数（首版不做运行时插件）。
package rules

import (
	"fmt"

	"medaudit/internal/facts"
)

// Risk 风险等级。
type Risk string

const (
	RiskHigh   Risk = "high"
	RiskMedium Risk = "medium"
	RiskLow    Risk = "low"
)

// RuleSpec 版本化规则定义（数据部分）。
type RuleSpec struct {
	ID          string
	Version     string
	Name        string
	Target      facts.TargetType
	Description string
	// Requires 评估所需的最少事实 kinds；缺失时结论为 UNKNOWN。
	Requires []facts.FactKind
	Risk     Risk
	// Remediation 整改建议。
	Remediation string
}

// TechnicalResult 单条技术结论。
type TechnicalResult struct {
	RuleID      string
	RuleVersion string
	RuleName    string
	Target      facts.TargetType
	Subject     string
	Conclusion  facts.Conclusion
	Risk        Risk
	Detail      string
	// Evidence 引用的事实 ID。
	Evidence []string
	// Missing 缺失的前置证据说明（UNKNOWN 时）。
	Missing string
}

// Baseline 版本化基线：允许的（主体 → 权限/角色）条目。
type Baseline struct {
	ID      string
	Version string
	Target  facts.TargetType
	Allows  []BaselineAllow
}

// BaselineAllow 单条允许：主体在某范围内拥有某权限/角色是业务必需的。
type BaselineAllow struct {
	Subject string // 主体稳定标识（进程键/user@host/登录名）
	Kind    string // "privilege" | "role" | "identity"
	Value   string // 权限名/角色名/身份描述
	Scope   string // 作用范围，可空
	Reason  string // 业务依据
}

// Allowed 判断（subject, kind, value, scope）是否在基线允许内。
func (b *Baseline) Allowed(subject, kind, value, scope string) bool {
	if b == nil {
		return false
	}
	for _, a := range b.Allows {
		if a.Subject == subject && a.Kind == kind && a.Value == value {
			if a.Scope == "" || scope == "" || a.Scope == scope {
				return true
			}
		}
	}
	return false
}

// EvalContext 评估上下文。
type EvalContext struct {
	Bundle   *facts.FactBundle
	Baseline *Baseline
	// 按 kind 索引的事实。
	ByKind map[facts.FactKind][]facts.Fact
}

// NewEvalContext 建索引。
func NewEvalContext(b *facts.FactBundle, baseline *Baseline) *EvalContext {
	c := &EvalContext{Bundle: b, Baseline: baseline, ByKind: map[facts.FactKind][]facts.Fact{}}
	for _, f := range b.Facts {
		c.ByKind[f.Kind] = append(c.ByKind[f.Kind], f)
	}
	return c
}

// CheckFunc 规则检查函数：返回命中项；空表示无问题（PASS）。
// 检查函数只读事实，不得产生副作用。
type CheckFunc func(*EvalContext) []CheckHit

// CheckHit 检查命中（一项待判定的发现）。
type CheckHit struct {
	Subject  string
	Detail   string
	Evidence []string
	Risk     Risk
}

// ruleEntry 注册表项。
type ruleEntry struct {
	spec  RuleSpec
	check CheckFunc
}

// Registry 规则注册表。
type Registry struct {
	rules []ruleEntry
	byID  map[string]int
}

// NewRegistry 建空注册表。
func NewRegistry() *Registry {
	return &Registry{byID: map[string]int{}}
}

// Register 注册规则；ID 重复则报错。
func (r *Registry) Register(spec RuleSpec, check CheckFunc) error {
	if _, ok := r.byID[spec.ID]; ok {
		return fmt.Errorf("规则 %s 重复注册", spec.ID)
	}
	r.byID[spec.ID] = len(r.rules)
	r.rules = append(r.rules, ruleEntry{spec: spec, check: check})
	return nil
}

// Rules 列出已注册规则。
func (r *Registry) Rules() []RuleSpec {
	out := make([]RuleSpec, 0, len(r.rules))
	for _, e := range r.rules {
		out = append(out, e.spec)
	}
	return out
}

// Evaluate 对事实包执行全部适用规则。
func (r *Registry) Evaluate(b *facts.FactBundle, baseline *Baseline) []TechnicalResult {
	ctx := NewEvalContext(b, baseline)
	var results []TechnicalResult
	for _, e := range r.rules {
		spec := e.spec
		// 目标不匹配 → NOT_APPLICABLE
		if spec.Target != b.Collector.Adapter {
			results = append(results, TechnicalResult{
				RuleID: spec.ID, RuleVersion: spec.Version, RuleName: spec.Name,
				Target: spec.Target, Conclusion: facts.ConclusionNotApplicable,
				Risk: spec.Risk, Detail: "规则目标与采集适配器不匹配",
			})
			continue
		}
		// 前置事实缺失 → UNKNOWN（不得填默认安全值）
		var missing []facts.FactKind
		for _, k := range spec.Requires {
			if len(ctx.ByKind[k]) == 0 {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			results = append(results, TechnicalResult{
				RuleID: spec.ID, RuleVersion: spec.Version, RuleName: spec.Name,
				Target: spec.Target, Conclusion: facts.ConclusionUnknown,
				Risk: spec.Risk, Missing: fmt.Sprintf("缺少前置事实: %v", missing),
				Detail: "证据不足，无法判定",
			})
			continue
		}
		hits := e.check(ctx)
		if len(hits) == 0 {
			results = append(results, TechnicalResult{
				RuleID: spec.ID, RuleVersion: spec.Version, RuleName: spec.Name,
				Target: spec.Target, Conclusion: facts.ConclusionPass,
				Risk: spec.Risk, Detail: "未发现违规",
			})
			continue
		}
		for _, h := range hits {
			risk := h.Risk
			if risk == "" {
				risk = spec.Risk
			}
			results = append(results, TechnicalResult{
				RuleID: spec.ID, RuleVersion: spec.Version, RuleName: spec.Name,
				Target: spec.Target, Subject: h.Subject,
				Conclusion: facts.ConclusionFail, Risk: risk,
				Detail: h.Detail, Evidence: h.Evidence,
			})
		}
	}
	return results
}
