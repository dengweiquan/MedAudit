package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"

	"medaudit/internal/platform"
	"medaudit/internal/rules"
)

// registerEvalRoutes 注册评估/基线/复核相关路由。
func registerEvalRoutes(mux *http.ServeMux, db *sql.DB, reg *rules.Registry) {
	// POST /api/v1/evaluations {bundle_id, baseline_id?}
	mux.HandleFunc("/api/v1/evaluations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			BundleID   string `json:"bundle_id"`
			BaselineID string `json:"baseline_id"`
			Bare       bool   `json:"bare"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BundleID == "" {
			http.Error(w, "bundle_id 必填", http.StatusBadRequest)
			return
		}
		// M35 自动屏蔽：未指定基线且非裸评时，自动套用该包所属医院的全部基线。
		summary, err := platform.EvaluateBundleAuto(db, reg, req.BundleID, req.BaselineID, req.Bare)
		if err != nil {
			http.Error(w, "评估失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, summary)
	})

	// GET /api/v1/findings?bundle_id=
	mux.HandleFunc("/api/v1/findings", func(w http.ResponseWriter, r *http.Request) {
		bundleID := r.URL.Query().Get("bundle_id")
		if bundleID == "" {
			http.Error(w, "bundle_id 必填", http.StatusBadRequest)
			return
		}
		rows, err := platform.ListFindings(db, bundleID)
		if err != nil {
			http.Error(w, "查询失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rows)
	})

	// /api/v1/findings/{id}/review|retest|retests|remediations 分发（M6 扩充复测与整改）
	mux.HandleFunc("/api/v1/findings/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/findings/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		findingID, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			http.Error(w, "finding id 非法", http.StatusBadRequest)
			return
		}
		switch {
		case parts[1] == "fix" && r.Method == http.MethodGet:
			script, supported, err := platform.FixScriptForFinding(db, findingID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !supported {
				writeJSON(w, map[string]any{"supported": false})
				return
			}
			writeJSON(w, map[string]any{"supported": true, "script": script})
		case parts[1] == "review" && r.Method == http.MethodPost:
			var req struct {
				HospitalID string `json:"hospital_id"`
				Decision   string `json:"decision"`
				Comment    string `json:"comment"`
				Reviewer   string `json:"reviewer"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "请求解析失败", http.StatusBadRequest)
				return
			}
			if err := platform.ReviewFinding(db, findingID, req.HospitalID, req.Decision, req.Comment, req.Reviewer); err != nil {
				http.Error(w, "复核失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]string{"status": "ok"})
		case parts[1] == "retest" && r.Method == http.MethodPost:
			var req struct {
				BundleID string `json:"bundle_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BundleID == "" {
				http.Error(w, "bundle_id 必填", http.StatusBadRequest)
				return
			}
			row, err := platform.RetestFinding(db, reg, findingID, req.BundleID)
			if err != nil {
				http.Error(w, "复测失败: "+err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, row)
		case parts[1] == "retests" && r.Method == http.MethodGet:
			rows, err := platform.ListRetests(db, findingID)
			if err != nil {
				http.Error(w, "查询失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, rows)
		case parts[1] == "remediations" && r.Method == http.MethodGet:
			rows, err := platform.ListRemediations(db, findingID)
			if err != nil {
				http.Error(w, "查询失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, rows)
		case parts[1] == "remediations" && r.Method == http.MethodPost:
			var req struct {
				Action  string `json:"action"`
				Status  string `json:"status"`
				ActedBy string `json:"acted_by"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "请求解析失败", http.StatusBadRequest)
				return
			}
			row, err := platform.AddRemediation(db, findingID, req.Action, req.Status, req.ActedBy)
			if err != nil {
				http.Error(w, "登记整改失败: "+err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, row)
		default:
			http.NotFound(w, r)
		}
	})

	// POST /api/v1/baselines, GET /api/v1/baselines?hospital_id=
	mux.HandleFunc("/api/v1/baselines", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var req struct {
				ID         string                `json:"id"`
				HospitalID string                `json:"hospital_id"`
				Target     string                `json:"target"`
				Allows     []rules.BaselineAllow `json:"allows"`
				CreatedBy  string                `json:"created_by"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
				http.Error(w, "id 必填", http.StatusBadRequest)
				return
			}
			if err := platform.CreateBaseline(db, req.ID, req.HospitalID, req.Target, req.Allows, req.CreatedBy); err != nil {
				http.Error(w, "创建基线失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, map[string]string{"status": "ok", "id": req.ID})
		case http.MethodGet:
			hospitalID := r.URL.Query().Get("hospital_id")
			rows, err := platform.ListBaselines(db, hospitalID)
			if err != nil {
				http.Error(w, "查询失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, rows)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// POST /api/v1/baselines/exempt 问题页一键加基线：
	// {finding_id, baseline_id? | new_baseline_id?, reason?, created_by?}
	mux.HandleFunc("/api/v1/baselines/exempt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			FindingID     int64  `json:"finding_id"`
			BaselineID    string `json:"baseline_id"`
			NewBaselineID string `json:"new_baseline_id"`
			Reason        string `json:"reason"`
			CreatedBy     string `json:"created_by"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.FindingID == 0 {
			http.Error(w, "finding_id 必填", http.StatusBadRequest)
			return
		}
		if req.Reason == "" {
			req.Reason = "问题页一键加入（已确认例外）"
		}
		res, err := platform.ExemptFinding(db, reg, req.FindingID, req.BaselineID, req.NewBaselineID, req.Reason, req.CreatedBy)
		if err != nil {
			if err == platform.ErrExemptionUnsupported {
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}
			http.Error(w, "一键豁免失败: "+err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, res)
	})

	// POST /api/v1/baselines/exempt-preview 预览推导结果（不落库）：{finding_id}
	mux.HandleFunc("/api/v1/baselines/exempt-preview", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			FindingID int64 `json:"finding_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.FindingID == 0 {
			http.Error(w, "finding_id 必填", http.StatusBadRequest)
			return
		}
		pv, err := platform.PreviewExemption(db, reg, req.FindingID)
		if err != nil {
			http.Error(w, "预览失败: "+err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, pv)
	})

	// POST /api/v1/baselines/remove-allow 删除一条放行项：
	// {baseline_id, subject, kind, value, scope}
	mux.HandleFunc("/api/v1/baselines/remove-allow", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			BaselineID string `json:"baseline_id"`
			Subject    string `json:"subject"`
			Kind       string `json:"kind"`
			Value      string `json:"value"`
			Scope      string `json:"scope"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BaselineID == "" {
			http.Error(w, "baseline_id 必填", http.StatusBadRequest)
			return
		}
		n, err := platform.RemoveBaselineAllow(db, req.BaselineID,
			rules.BaselineAllow{Subject: req.Subject, Kind: req.Kind, Value: req.Value, Scope: req.Scope})
		if err != nil {
			http.Error(w, "删除放行项失败: "+err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "removed": n})
	})

	// PUT /api/v1/baselines/{id} 修改放行项（整体替换，版本+1；ID/医院/目标不动）；
	// DELETE /api/v1/baselines/{id} 删除整条基线（已存问题与报告不动）。
	// 注意：/api/v1/baselines/exempt 等精确路径优先于此前缀，不受影响。
	mux.HandleFunc("/api/v1/baselines/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/baselines/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var req struct {
				Allows []rules.BaselineAllow `json:"allows"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "请求解析失败", http.StatusBadRequest)
				return
			}
			if err := platform.UpdateBaselineAllows(db, id, req.Allows); err != nil {
				http.Error(w, "修改基线失败: "+err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]string{"status": "ok", "id": id})
		case http.MethodDelete:
			if err := platform.DeleteBaseline(db, id); err != nil {
				http.Error(w, "删除基线失败: "+err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]string{"status": "ok", "id": id})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// GET /api/v1/rules
	// GET /api/v1/compliance/frameworks：全部合规框架及是否进入报告。
	mux.HandleFunc("/api/v1/compliance/frameworks", func(w http.ResponseWriter, r *http.Request) {
		enabled, errs := platform.EnabledFrameworks()
		on := map[string]bool{}
		for _, f := range enabled {
			on[f.ID] = true
		}
		dir := os.Getenv("MEDAUDIT_COMPLIANCE_DIR")
		if dir == "" {
			dir = "/etc/medaudit/compliance"
		}
		all, _ := rules.LoadFrameworks(dir)
		type fwOut struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Short   string `json:"short"`
			Status  string `json:"status"`
			Source  string `json:"source"`
			Clauses int    `json:"clauses"`
			Enabled bool   `json:"enabled"`
		}
		out := []fwOut{}
		for _, f := range all {
			out = append(out, fwOut{f.ID, f.Name, f.Short, f.Status, f.Source, len(f.Controls), on[f.ID]})
		}
		if errs == nil {
			errs = []string{}
		}
		writeJSON(w, map[string]any{"items": out, "errors": errs})
	})

	mux.HandleFunc("/api/v1/rules", func(w http.ResponseWriter, r *http.Request) {
		type ruleOut struct {
			rules.RuleSpec
			Compliance []rules.Control
		}
		specs := reg.Rules()
		out := make([]ruleOut, len(specs))
		for i, s := range specs {
			out[i] = ruleOut{RuleSpec: s, Compliance: rules.ControlsFor(s.ID)}
		}
		writeJSON(w, out)
	})

	// POST /api/v1/reports {hospital_id, plan_id, bundle_id, created_by}
	mux.HandleFunc("/api/v1/reports", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			rows, err := platform.ListReports(db)
			if err != nil {
				http.Error(w, "查询失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, rows)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			HospitalID string `json:"hospital_id"`
			PlanID     string `json:"plan_id"`
			BundleID   string `json:"bundle_id"`
			CreatedBy  string `json:"created_by"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BundleID == "" {
			http.Error(w, "bundle_id 必填", http.StatusBadRequest)
			return
		}
		id, err := platform.GenerateReport(db, req.HospitalID, req.PlanID, req.BundleID, req.CreatedBy)
		if err != nil {
			http.Error(w, "报告生成失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]string{"status": "ok", "report_id": id})
	})
}
