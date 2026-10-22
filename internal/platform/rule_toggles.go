package platform

import (
	"database/sql"
	"fmt"
)

// RuleToggle 规则启停行（本站作用域）。表中只存被操作过的规则；
// 无行 = 启用（默认）。enabled=0 表示工程师已关闭该检查项。
type RuleToggle struct {
	RuleID    string `json:"rule_id"`
	Enabled   bool   `json:"enabled"`
	Reason    string `json:"reason"`
	UpdatedBy string `json:"updated_by"`
	UpdatedAt string `json:"updated_at"`
}

// ListRuleToggles 列出全部启停记录（按规则 ID）。
func ListRuleToggles(db *sql.DB) ([]RuleToggle, error) {
	rows, err := db.Query(
		`SELECT rule_id, enabled, reason, updated_by,
		        strftime('%Y-%m-%d %H:%M:%S', updated_at)
		 FROM rule_toggles ORDER BY rule_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RuleToggle{}
	for rows.Next() {
		var t RuleToggle
		var en int
		if err := rows.Scan(&t.RuleID, &en, &t.Reason, &t.UpdatedBy, &t.UpdatedAt); err != nil {
			return nil, err
		}
		t.Enabled = en != 0
		out = append(out, t)
	}
	return out, rows.Err()
}

// DisabledRuleIDs 返回已关闭规则的集合，供评估过滤。
func DisabledRuleIDs(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query(`SELECT rule_id FROM rule_toggles WHERE enabled = 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// IsRuleDisabled 单条查询（复测等单点校验用）。
func IsRuleDisabled(db *sql.DB, ruleID string) (bool, error) {
	var en int
	err := db.QueryRow(`SELECT enabled FROM rule_toggles WHERE rule_id = ?`, ruleID).Scan(&en)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return en == 0, nil
}

// SetRuleToggle 设置一条规则的启停（upsert，留痕操作人与原因）。
func SetRuleToggle(db *sql.DB, ruleID string, enabled bool, reason, by string) error {
	if ruleID == "" {
		return fmt.Errorf("rule_id 必填")
	}
	en := 0
	if enabled {
		en = 1
	}
	_, err := db.Exec(
		`INSERT INTO rule_toggles (rule_id, enabled, reason, updated_by, updated_at)
		 VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(rule_id) DO UPDATE SET
		   enabled = excluded.enabled, reason = excluded.reason,
		   updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP`,
		ruleID, en, reason, by)
	return err
}
