package rules

import (
	"fmt"
	"strings"

	"medaudit/internal/facts"
)

// EvidenceStatus 证据就绪状态：规则在判定前对证据的门控结论。
type EvidenceStatus int

const (
	// EvidenceReady 证据齐全，可以判定。
	EvidenceReady EvidenceStatus = iota
	// EvidenceMissing 证据缺失、被拒绝、失败或不可信，无法判定 → UNKNOWN。
	EvidenceMissing
	// EvidencePartial 证据不完整（截断）：有命中仍判 FAIL，无命中则 UNKNOWN（不得判 PASS）。
	EvidencePartial
	// EvidenceNotApplicable 证据证明本规则确实不适用 → NOT_APPLICABLE。
	EvidenceNotApplicable
)

// EvidenceCheck 可选证据门控：非 nil 时评估先于 check 执行。
// 返回（状态，原因）。未声明的旧规则保持原有语义（不门控）。
type EvidenceCheck func(c *EvalContext) (EvidenceStatus, string)

// receiptVerdict 按收据判定某采集项（TemplateID == source）的证据状态。
// 优先级（从严）：被拒绝 > 失败 > 无收据 > 截断 > 成功。
// 该函数只看收据，不看事实：事实必须另由调用方匹配，避免无收据背书的事实被采信。
func receiptVerdict(c *EvalContext, source string) (EvidenceStatus, string) {
	var saw, failed, truncated bool
	failedStage := ""
	for _, rc := range c.Bundle.Receipts {
		if rc.TemplateID != source {
			continue
		}
		saw = true
		switch rc.Status {
		case "denied":
			return EvidenceMissing, fmt.Sprintf("%s 采集被拒绝（权限不足），无法判定", source)
		case "failed":
			failed = true
			if failedStage == "" {
				failedStage = rc.ErrorStage
			}
		default:
			if rc.Status == "partial" || rc.Truncated {
				truncated = true
			}
		}
	}
	if !saw {
		return EvidenceMissing, fmt.Sprintf("未采集到 %s 证据（旧包或未执行），无法判定", source)
	}
	if failed {
		if failedStage == "" {
			failedStage = "未知阶段"
		}
		return EvidenceMissing, fmt.Sprintf("%s 采集失败（%s），无法判定", source, failedStage)
	}
	if truncated {
		return EvidencePartial, fmt.Sprintf("%s 证据被截断，不完整，无法确认通过", source)
	}
	return EvidenceReady, ""
}

// EvidenceSource 声明某采集项的证据门控（单收据、全局类证据，如服务器配置项）。
//   - 收据被拒绝 / 失败 / 缺失 → Missing；截断 → Partial；
//   - 收据成功后，按 Observed 事实匹配：attr 值属于 keys 之一（keys 为空时只要求有 Observed 事实）；
//   - 成功但零匹配行：emptyOK 为 true 时 Ready（由 check 解释空集语义，如“未配置任何审计”），
//     否则 Missing。
//
// source 即模板 ID（与事实 Source 一致）；attr 为事实属性键（如 pg.settings 的 "name"）。
func EvidenceSource(source, attr string, keys []string, emptyOK bool) EvidenceCheck {
	return func(c *EvalContext) (EvidenceStatus, string) {
		if st, reason := receiptVerdict(c, source); st != EvidenceReady {
			return st, reason
		}
		for _, f := range c.Bundle.Facts {
			if f.Source != source || f.Status != facts.StatusObserved {
				continue
			}
			if len(keys) == 0 || contains(keys, f.Attributes[attr]) {
				return EvidenceReady, ""
			}
		}
		if emptyOK {
			return EvidenceReady, ""
		}
		if len(keys) == 0 {
			return EvidenceMissing, fmt.Sprintf("%s 查询成功但无事实，无法判定", source)
		}
		return EvidenceMissing, fmt.Sprintf("%s 查询成功但未见 %s∈{%s} 的事实，无法判定",
			source, attr, strings.Join(keys, ","))
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// EvidenceSourceValue 在 EvidenceSource 基础上再验证值字段：键匹配的事实
// 其值属性必须存在且被 valid 接受（存在、可解析、值域合法），否则 Missing。
// 键存在但值缺失/非法时不得 Ready——否则 check 见不到违规值会误判 PASS
// （如 pg.settings 只有 name=ssl 而 setting 缺失/非法时，ssl_off 的 check
// 找不到 off 值即无命中，直接 PASS）。
func EvidenceSourceValue(source, keyAttr string, keys []string, valueAttr string, valid func(string) bool, emptyOK bool) EvidenceCheck {
	return func(c *EvalContext) (EvidenceStatus, string) {
		if st, reason := receiptVerdict(c, source); st != EvidenceReady {
			return st, reason
		}
		var keySeen bool
		for _, f := range c.Bundle.Facts {
			if f.Source != source || f.Status != facts.StatusObserved {
				continue
			}
			if len(keys) > 0 && !contains(keys, f.Attributes[keyAttr]) {
				continue
			}
			keySeen = true
			if valid(f.Attributes[valueAttr]) {
				return EvidenceReady, ""
			}
		}
		if emptyOK {
			return EvidenceReady, ""
		}
		if !keySeen {
			if len(keys) == 0 {
				return EvidenceMissing, fmt.Sprintf("%s 查询成功但无事实，无法判定", source)
			}
			return EvidenceMissing, fmt.Sprintf("%s 查询成功但未见 %s∈{%s} 的事实，无法判定",
				source, keyAttr, strings.Join(keys, ","))
		}
		return EvidenceMissing, fmt.Sprintf("%s 的 %s 事实值 %s 缺失或非法，无法判定",
			source, keyAttr, valueAttr)
	}
}

// pgBoolValue PG 布尔型设置的可接受值（pg_settings 的布尔量纲）。
func pgBoolValue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "off", "true", "false", "yes", "no", "1", "0":
		return true
	}
	return false
}

// auditTrailValue Oracle AUDIT_TRAIL 的可接受值（传统审计参数量纲）。
func auditTrailValue(v string) bool {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "NONE", "OS", "DB", "XML", "DB,EXTENDED", "XML,EXTENDED":
		return true
	}
	return false
}
