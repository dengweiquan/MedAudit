package platform

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"medaudit/internal/facts"
	"medaudit/internal/rules"
)

// ErrExemptionUnsupported 该规则没有基线钩子，不支持一键豁免。
var ErrExemptionUnsupported = errors.New("该规则不支持基线豁免（可使用规则启停处理整类检查）")

type findingDetailJSON struct {
	Evidence []string `json:"evidence"`
}

// deriveExemptionAllows 依据一条 FAIL finding 的证据事实推导基线放行项，
// 与各规则内 Baseline.Allowed 的调用口径逐条对应（subject/kind/value/scope）。
// ok=false 表示该规则不支持基线豁免。
func deriveExemptionAllows(ruleID, subject string, ev []facts.Fact) ([]rules.BaselineAllow, bool) {
	one := func(s, k, v, sc string) []rules.BaselineAllow {
		return []rules.BaselineAllow{{Subject: s, Kind: k, Value: v, Scope: sc}}
	}
	privs := []facts.Fact{}
	for _, f := range ev {
		if f.Kind == facts.FactPrivilege {
			privs = append(privs, f)
		}
	}
	privAllows := func(subj, scopeOverride string, grant bool) []rules.BaselineAllow {
		var out []rules.BaselineAllow
		for _, f := range privs {
			priv := f.Attributes["privilege"]
			if priv == "" {
				continue
			}
			if grant {
				priv += ":grant"
			}
			sc := f.Scope
			if scopeOverride != "" {
				sc = scopeOverride
			}
			out = append(out, rules.BaselineAllow{Subject: subj, Kind: "privilege", Value: priv, Scope: sc})
		}
		return out
	}

	switch ruleID {
	// ---- 静态口径（仅主体） ----
	case "db.oracle.dba_role", "db.oracle.cdb_dba_in_pdb":
		return one(subject, "role", "DBA", ""), true
	case "db.oracle.default_account_open":
		return one(subject, "identity", "default-account-open", ""), true
	case "db.pg.superuser":
		return one(subject, "role", "superuser", ""), true
	case "db.mssql.sysadmin":
		return one(subject, "role", "sysadmin", "server"), true
	case "os.windows.unexpected_admin":
		return one(subject, "identity", subject, ""), true
	case "os.linux.sudo_all", "os.hpux.sudo_all":
		return one(subject, "sudo", "ALL", ""), true
	case "db.mysql.remote_no_tls":
		return one(subject, "tls", "none", ""), true
	case "os.hpux.multiple_uid0":
		return one(subject, "identity", "uid0", ""), true
	case "os.hpux.inetd_risky_service":
		return one(subject, "service", "inetd", ""), true
	case "os.hpux.setuid_unexpected":
		return one(subject, "setuid", "setuid-root", ""), true
	case "mw.weblogic.console_deployed":
		return one(subject, "deployment", "console", ""), true
	case "mw.iis.apppool_system":
		return one(subject, "identity", "LocalSystem", ""), true
	case "mw.tomcat.run_as_root", "mw.nginx.run_as_root", "mw.weblogic.run_as_root":
		return one(subject, "identity", "run-as-root", ""), true
	case "db.pg.listen_all":
		return one("server", "settings", "listen_all", ""), true

	// ---- 权限事实推导 ----
	case "db.mysql.global_admin":
		return privAllows(subject, "*.*", false), true
	case "db.mysql.grant_option":
		return privAllows(subject, "*.*", true), true
	case "db.oracle.any_privilege", "db.oracle.sys_schema_grant":
		return privAllows(subject, "", false), true
	case "db.oracle.public_object_grant":
		return privAllows("PUBLIC", "", false), true
	case "db.oracle.grant_option_spread":
		return privAllows(subject, "", true), true
	case "db.oracle.sysdba_pwfile":
		var out []rules.BaselineAllow
		for _, f := range privs {
			priv := strings.ToUpper(f.Attributes["privilege"])
			if priv == "SYSDBA" || priv == "SYSOPER" {
				out = append(out, rules.BaselineAllow{Subject: subject, Kind: "privilege", Value: priv, Scope: "pwfile"})
			}
		}
		return out, true
	case "db.mssql.control_server":
		var out []rules.BaselineAllow
		for range privs {
			out = append(out, rules.BaselineAllow{Subject: subject, Kind: "privilege", Value: "CONTROL SERVER", Scope: "server"})
		}
		if len(out) == 0 {
			out = one(subject, "privilege", "CONTROL SERVER", "server")
		}
		return out, true

	// ---- 事实属性推导 ----
	case "os.linux.high_capabilities":
		var out []rules.BaselineAllow
		for _, f := range ev {
			if caps := f.Attributes["caps"]; caps != "" {
				out = append(out, rules.BaselineAllow{Subject: subject, Kind: "identity", Value: "caps:" + caps})
			}
		}
		return out, true
	case "db.pg.dangerous_role_attrs":
		labels := []struct{ attr, label string }{
			{"can_create_role", "CREATEROLE"}, {"can_create_db", "CREATEDB"},
			{"replication", "REPLICATION"}, {"bypass_rls", "BYPASSRLS"},
		}
		var out []rules.BaselineAllow
		for _, f := range ev {
			if f.Kind != facts.FactIdentity || f.Source != "pg.roles" {
				continue
			}
			for _, d := range labels {
				if f.Attributes[d.attr] == "true" {
					out = append(out, rules.BaselineAllow{Subject: subject, Kind: "role_attr", Value: d.label})
				}
			}
		}
		return out, true
	case "db.pg.hba_trust":
		var out []rules.BaselineAllow
		for _, f := range ev {
			if f.Kind == facts.FactAccountConfig {
				out = append(out, rules.BaselineAllow{Subject: subject, Kind: "hba", Value: "trust", Scope: f.Attributes["address"]})
			}
		}
		return out, true
	case "db.pg.hba_open_network":
		var out []rules.BaselineAllow
		for _, f := range ev {
			if f.Kind == facts.FactAccountConfig {
				out = append(out, rules.BaselineAllow{Subject: subject, Kind: "hba", Value: "open_network", Scope: f.Attributes["address"]})
			}
		}
		return out, true
	case "db.oracle.profile_password_policy":
		var out []rules.BaselineAllow
		for _, f := range ev {
			if f.Kind == facts.FactAccountConfig && f.Attributes["resource"] != "" {
				out = append(out, rules.BaselineAllow{Subject: subject, Kind: "profile", Value: f.Attributes["resource"]})
			}
		}
		return out, true
	case "db.mssql.xp_cmdshell", "db.mssql.clr_enabled", "db.mssql.cross_db_chaining", "db.mssql.adhoc_distributed":
		if len(ev) > 0 {
			return one("server", "config", ev[0].Subject, ""), true
		}
		return nil, true
	case "db.mysql.local_infile", "db.mysql.general_log_on", "db.mysql.name_resolve_on":
		for _, f := range ev {
			if n := f.Attributes["name"]; n != "" {
				return one("global", "variable", n, ""), true
			}
		}
		return nil, true
	case "mw.tomcat.manager_deployed":
		var out []rules.BaselineAllow
		for _, f := range ev {
			if k := f.Attributes["app_kind"]; k != "" {
				out = append(out, rules.BaselineAllow{Subject: subject, Kind: "deployment", Value: k})
			}
		}
		return out, true
	case "mw.tomcat.console_admin":
		adminRoles := map[string]bool{
			"manager-gui": true, "manager-script": true, "manager-jmx": true,
			"admin-gui": true, "admin-script": true,
		}
		var out []rules.BaselineAllow
		for _, f := range ev {
			if f.Kind != facts.FactIdentity {
				continue
			}
			for _, role := range strings.Split(f.Attributes["roles"], ",") {
				role = strings.TrimSpace(role)
				if adminRoles[role] {
					out = append(out, rules.BaselineAllow{Subject: subject, Kind: "role", Value: role})
				}
			}
		}
		return out, true
	case "mw.iis.anon_open":
		for _, f := range ev {
			if site := f.Attributes["site"]; site != "" {
				return one(site, "identity", "anonymous-open", ""), true
			}
		}
		return one(subject, "identity", "anonymous-open", ""), true
	}
	return nil, false
}

func allowKey(a rules.BaselineAllow) string {
	return a.Subject + "\x00" + a.Kind + "\x00" + a.Value + "\x00" + a.Scope
}

func dedupeAllows(in []rules.BaselineAllow) []rules.BaselineAllow {
	seen := map[string]bool{}
	var out []rules.BaselineAllow
	for _, a := range in {
		k := allowKey(a)
		if !seen[k] {
			seen[k] = true
			out = append(out, a)
		}
	}
	return out
}

// AddBaselineAllows 向既有基线追加放行项（四元组去重），返回实际新增的项。
func AddBaselineAllows(db *sql.DB, baselineID string, allows []rules.BaselineAllow) ([]rules.BaselineAllow, error) {
	b, err := LoadBaseline(db, baselineID)
	if err != nil {
		return nil, err
	}
	existing := map[string]bool{}
	for _, a := range b.Allows {
		existing[allowKey(a)] = true
	}
	var added []rules.BaselineAllow
	for _, a := range allows {
		if !existing[allowKey(a)] {
			b.Allows = append(b.Allows, a)
			existing[allowKey(a)] = true
			added = append(added, a)
		}
	}
	if len(added) == 0 {
		return []rules.BaselineAllow{}, nil
	}
	spec, err := json.Marshal(map[string]any{"allows": b.Allows})
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`UPDATE baselines SET spec = ? WHERE id = ?`, string(spec), baselineID)
	if err != nil {
		return nil, err
	}
	return added, nil
}

// RemoveBaselineAllow 从基线删除一条放行项（四元组精确匹配），返回删除条数。
func RemoveBaselineAllow(db *sql.DB, baselineID string, target rules.BaselineAllow) (int, error) {
	b, err := LoadBaseline(db, baselineID)
	if err != nil {
		return 0, err
	}
	var kept []rules.BaselineAllow
	removed := 0
	for _, a := range b.Allows {
		if allowKey(a) == allowKey(target) {
			removed++
			continue
		}
		kept = append(kept, a)
	}
	if removed == 0 {
		return 0, nil
	}
	if kept == nil {
		kept = []rules.BaselineAllow{}
	}
	spec, err := json.Marshal(map[string]any{"allows": kept})
	if err != nil {
		return 0, err
	}
	_, err = db.Exec(`UPDATE baselines SET spec = ? WHERE id = ?`, string(spec), baselineID)
	return removed, err
}

// ExemptResult 一键豁免结果。
type ExemptResult struct {
	BaselineID string                `json:"baseline_id"`
	Target     string                `json:"target"`
	HospitalID string                `json:"hospital_id"`
	Added      []rules.BaselineAllow `json:"added"`
	Skipped    int                   `json:"skipped_existing"`
}

// ExemptionPreview 一键豁免预览（不落库）。
type ExemptionPreview struct {
	Supported  bool                  `json:"supported"`
	RuleID     string                `json:"rule_id"`
	Subject    string                `json:"subject"`
	Target     string                `json:"target"`
	HospitalID string                `json:"hospital_id"`
	Allows     []rules.BaselineAllow `json:"allows"`
}

// prepareExemption 载入 finding 并推导放行项（ExemptFinding 与预览共用）。
func prepareExemption(db *sql.DB, reg *rules.Registry, findingID int64) (*ExemptionPreview, error) {
	var bundleID, ruleID, subject, conclusion, detail string
	err := db.QueryRow(`SELECT bundle_id, rule_id, subject, conclusion, detail FROM findings WHERE id = ?`, findingID).
		Scan(&bundleID, &ruleID, &subject, &conclusion, &detail)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("finding %d 不存在", findingID)
	}
	if err != nil {
		return nil, err
	}
	if conclusion != "FAIL" {
		return nil, fmt.Errorf("仅 FAIL 结论可加入基线（当前 %s）", conclusion)
	}
	var hospitalID string
	if err := db.QueryRow(`SELECT hospital_id FROM fact_bundles WHERE id = ?`, bundleID).Scan(&hospitalID); err != nil {
		return nil, fmt.Errorf("事实包 %s 元数据缺失: %w", bundleID, err)
	}
	target := ""
	for _, r := range reg.Rules() {
		if r.ID == ruleID {
			target = string(r.Target)
			break
		}
	}
	if target == "" {
		return nil, fmt.Errorf("规则 %s 未在注册表中找到", ruleID)
	}
	bundle, err := loadBundle(db, bundleID)
	if err != nil {
		return nil, err
	}
	var dj findingDetailJSON
	_ = json.Unmarshal([]byte(detail), &dj)
	byID := map[string]facts.Fact{}
	for _, f := range bundle.Facts {
		byID[f.FactID] = f
	}
	var ev []facts.Fact
	for _, id := range dj.Evidence {
		if f, ok := byID[id]; ok {
			ev = append(ev, f)
		}
	}
	allows, supported := deriveExemptionAllows(ruleID, subject, ev)
	pv := &ExemptionPreview{Supported: supported, RuleID: ruleID, Subject: subject, Target: target, HospitalID: hospitalID}
	if !supported {
		return pv, nil
	}
	pv.Allows = dedupeAllows(allows)
	return pv, nil
}

// PreviewExemption 预览一条 finding 可推导的放行项（不落库）。
func PreviewExemption(db *sql.DB, reg *rules.Registry, findingID int64) (*ExemptionPreview, error) {
	return prepareExemption(db, reg, findingID)
}

// ExemptFinding 把一条 FAIL finding 推导出的放行项加入基线：
// baselineID 非空则追加（须同院同目标）；否则以 newBaselineID 新建。
func ExemptFinding(db *sql.DB, reg *rules.Registry, findingID int64, baselineID, newBaselineID, reason, createdBy string) (*ExemptResult, error) {
	pv, err := prepareExemption(db, reg, findingID)
	if err != nil {
		return nil, err
	}
	if !pv.Supported {
		return nil, ErrExemptionUnsupported
	}
	hospitalID, target := pv.HospitalID, pv.Target
	allows := pv.Allows
	if len(allows) == 0 {
		return nil, fmt.Errorf("未能从该问题的证据事实推导出放行项，请改用基线页手工登记")
	}
	for i := range allows {
		if allows[i].Reason == "" {
			allows[i].Reason = reason
		}
	}
	res := &ExemptResult{Target: target, HospitalID: hospitalID}
	if baselineID != "" {
		var bHosp, bTarget string
		err := db.QueryRow(`SELECT hospital_id, target FROM baselines WHERE id = ?`, baselineID).Scan(&bHosp, &bTarget)
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("基线 %s 不存在", baselineID)
		}
		if err != nil {
			return nil, err
		}
		if bHosp != hospitalID || bTarget != target {
			return nil, fmt.Errorf("基线 %s 归属（%s/%s）与该问题（%s/%s）不一致", baselineID, bHosp, bTarget, hospitalID, target)
		}
		added, err := AddBaselineAllows(db, baselineID, allows)
		if err != nil {
			return nil, err
		}
		res.BaselineID = baselineID
		res.Added = added
		res.Skipped = len(allows) - len(added)
		return res, nil
	}
	if newBaselineID == "" {
		return nil, fmt.Errorf("baseline_id 与 new_baseline_id 须给其一")
	}
	if err := CreateBaseline(db, newBaselineID, hospitalID, target, allows, createdBy); err != nil {
		return nil, err
	}
	res.BaselineID = newBaselineID
	res.Added = allows
	return res, nil
}
