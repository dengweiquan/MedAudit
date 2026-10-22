package main

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"medaudit/internal/platform"
	"medaudit/internal/rules"
)

// M17 规则启停（本站作用域）：工程师关闭的检查项评估时整体跳过。
// GET /api/v1/rule-toggles        → 全部启停记录（无记录的规则默认启用）
// PUT /api/v1/rule-toggles        → {rule_id, enabled, reason, updated_by}
func registerRuleToggleRoutes(mux *http.ServeMux, db *sql.DB, reg *rules.Registry) {
	mux.HandleFunc("/api/v1/rule-toggles", func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			http.Error(w, "平台库未配置", http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case http.MethodGet:
			list, err := platform.ListRuleToggles(db)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, list)
		case http.MethodPut:
			var req struct {
				RuleID    string `json:"rule_id"`
				Enabled   bool   `json:"enabled"`
				Reason    string `json:"reason"`
				UpdatedBy string `json:"updated_by"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RuleID == "" {
				http.Error(w, "rule_id 必填", http.StatusBadRequest)
				return
			}
			known := false
			for _, rule := range reg.Rules() {
				if rule.ID == req.RuleID {
					known = true
					break
				}
			}
			if !known {
				http.Error(w, "未知规则 "+req.RuleID, http.StatusBadRequest)
				return
			}
			if !req.Enabled && req.Reason == "" {
				http.Error(w, "关闭检查项必须填写原因（如：现场 Oracle SYS/SYSTEM 为厂商必需账号）", http.StatusBadRequest)
				return
			}
			if err := platform.SetRuleToggle(db, req.RuleID, req.Enabled, req.Reason, req.UpdatedBy); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]string{"status": "ok", "rule_id": req.RuleID})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}
