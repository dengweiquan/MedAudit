// Package remediation 为 FAIL finding 生成修复/回滚脚本（M15）。
//
// 边界：平台只生成、人工执行，绝不自动改目标权限。每份脚本是四件套：
// Precheck（只读确认现状）→ Fix（修复）→ Verify（修复后复查）→ Rollback
// （生成时点按证据事实捕获的精确逆操作，含 GRANT OPTION/ADMIN OPTION
// 与配置原值）。证据不足以构造精确命令时返回 nil，报告按「程序性整改」计数，
// 不伪造命令。
package remediation

import (
	"strings"

	"medaudit/internal/facts"
)

// Script 一条 finding 的修复/回滚脚本。字段均为可直接粘贴执行的文本（可多行）。
type Script struct {
	FindingID int64  `json:"finding_id"`
	RuleID    string `json:"rule_id"`
	Subject   string `json:"subject"`
	Scope     string `json:"scope,omitempty"`
	Precheck  string `json:"precheck"`
	Fix       string `json:"fix"`
	Verify    string `json:"verify"`
	Rollback  string `json:"rollback"`
	Note      string `json:"note,omitempty"`
}

type generator func(subject string, ev []facts.Fact) *Script

var generators = map[string]generator{}

// Generate 按 rule_id 分发生成；无模板或证据不足返回 nil。
func Generate(ruleID, subject string, ev []facts.Fact) *Script {
	g, ok := generators[ruleID]
	if !ok || len(ev) == 0 {
		return nil
	}
	return g(subject, ev)
}

// HasTemplate 该规则在一期模板范围内（与证据是否充足无关，用于报告覆盖计数）。
func HasTemplate(ruleID string) bool {
	_, ok := generators[ruleID]
	return ok
}

// ---- 通用助手 ----

// splitAcct 拆 MySQL 账号 subject（user@host，按最后一个 @ 切分）。
func splitAcct(subject string) (user, host string, ok bool) {
	i := strings.LastIndex(subject, "@")
	if i <= 0 || i == len(subject)-1 {
		return "", "", false
	}
	return subject[:i], subject[i+1:], true
}

// myAcct 渲染 'user'@'host'（转义单引号与反斜杠）。
func myAcct(subject string) string {
	u, h, ok := splitAcct(subject)
	if !ok {
		return "'" + strings.ReplaceAll(subject, "'", "''") + "'"
	}
	esc := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		return strings.ReplaceAll(s, "'", "''")
	}
	return "'" + esc(u) + "'@'" + esc(h) + "'"
}

// dq 双引号标识符（PG/Oracle 通用）：内部双引号翻倍。
func dq(ident string) string {
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
}

// br SQL Server 方括号标识符。
func br(ident string) string {
	return "[" + strings.ReplaceAll(ident, "]", "]]") + "]"
}

// sq 单引号字符串字面量。
func sq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// privFacts 从证据中挑授权类事实（带 privilege 属性），可按 source 过滤（空=全部）。
func privFacts(ev []facts.Fact, source string) []facts.Fact {
	var out []facts.Fact
	for _, f := range ev {
		if f.Attributes["privilege"] == "" {
			continue
		}
		if source != "" && f.Source != source {
			continue
		}
		out = append(out, f)
	}
	return out
}

// firstFact 返回证据中第一个指定 source 的事实。
func firstFact(ev []facts.Fact, source string) *facts.Fact {
	for i := range ev {
		if ev[i].Source == source {
			return &ev[i]
		}
	}
	return nil
}

// grantOpt 事实的 Grantable（nil 视为 false）。
func grantOpt(f facts.Fact) bool {
	return f.Grantable != nil && *f.Grantable
}

// joinNonEmpty 以 sep 连接非空段。
func joinNonEmpty(sep string, parts ...string) string {
	var out []string
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}
