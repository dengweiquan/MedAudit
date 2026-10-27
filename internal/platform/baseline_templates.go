package platform

import (
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"medaudit/internal/rules"
)

// 基线模板：常见内置账号与 HIS/LIS/PACS 厂商账号的放行项，实施时一键套用为本院基线。
// 内置模板随程序发布；站点可在 MEDAUDIT_BASELINE_TEMPLATE_DIR（缺省
// /etc/medaudit/baseline-templates）放 *.yaml 增加或按同 id 覆盖。
// 主体写成 {名称} 的为占位符，套用时必须填成现场实际账号。

//go:embed baseline_templates/*.yaml
var builtinTemplates embed.FS

// TemplateEntry 模板中的一条放行项。
type TemplateEntry struct {
	Subject string `yaml:"subject" json:"subject"`
	Kind    string `yaml:"kind" json:"kind"`
	Value   string `yaml:"value" json:"value"`
	Scope   string `yaml:"scope" json:"scope"`
	Reason  string `yaml:"reason" json:"reason"`
}

// BaselineTemplate 一个基线模板。
type BaselineTemplate struct {
	ID           string          `yaml:"id" json:"id"`
	Name         string          `yaml:"name" json:"name"`
	System       string          `yaml:"system" json:"system"` // HIS | LIS | PACS | 通用 …
	Target       string          `yaml:"target" json:"target"`
	Status       string          `yaml:"status" json:"status"` // verified | draft
	Description  string          `yaml:"description" json:"description"`
	Entries      []TemplateEntry `yaml:"entries" json:"entries"`
	Placeholders []string        `yaml:"-" json:"placeholders"`
	Source       string          `yaml:"-" json:"source"` // builtin | site
}

var placeholderRe = regexp.MustCompile(`\{[^{}]+\}`)

// templateKinds 与规则引擎 Baseline.Allowed 使用的 kind 一致。
var templateKinds = map[string]bool{
	"privilege": true, "role": true, "identity": true, "sudo": true, "tls": true,
	"service": true, "setuid": true, "deployment": true, "settings": true,
	"role_attr": true, "hba": true, "profile": true, "config": true, "variable": true,
}

func parseTemplate(data []byte, source string) (*BaselineTemplate, error) {
	var t BaselineTemplate
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	if t.ID == "" || t.Name == "" || t.Target == "" || len(t.Entries) == 0 {
		return nil, fmt.Errorf("模板缺少 id/name/target/entries")
	}
	if t.Status != "verified" {
		t.Status = "draft"
	}
	seen := map[string]bool{}
	for i, e := range t.Entries {
		if e.Subject == "" || e.Value == "" || !templateKinds[e.Kind] {
			return nil, fmt.Errorf("第 %d 条放行项无效（subject/value 必填，kind=%q）", i+1, e.Kind)
		}
		for _, p := range placeholderRe.FindAllString(e.Subject, -1) {
			if !seen[p] {
				seen[p] = true
				t.Placeholders = append(t.Placeholders, p)
			}
		}
	}
	if t.Placeholders == nil {
		t.Placeholders = []string{}
	}
	t.Source = source
	return &t, nil
}

func templateDir() string {
	if d := os.Getenv("MEDAUDIT_BASELINE_TEMPLATE_DIR"); d != "" {
		return d
	}
	return "/etc/medaudit/baseline-templates"
}

// ListBaselineTemplates 内置模板 + 站点模板（同 id 站点覆盖内置），按系统、名称排序。
// 站点模板解析失败的跳过并在 errs 中返回说明。
func ListBaselineTemplates() (out []BaselineTemplate, errs []string) {
	byID := map[string]BaselineTemplate{}
	entries, _ := builtinTemplates.ReadDir("baseline_templates")
	for _, e := range entries {
		data, err := builtinTemplates.ReadFile("baseline_templates/" + e.Name())
		if err != nil {
			continue
		}
		t, err := parseTemplate(data, "builtin")
		if err != nil {
			errs = append(errs, "内置模板 "+e.Name()+": "+err.Error())
			continue
		}
		byID[t.ID] = *t
	}
	files, _ := filepath.Glob(filepath.Join(templateDir(), "*.yaml"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			errs = append(errs, f+": "+err.Error())
			continue
		}
		t, err := parseTemplate(data, "site")
		if err != nil {
			errs = append(errs, f+": "+err.Error())
			continue
		}
		byID[t.ID] = *t
	}
	rank := map[string]int{"HIS": 0, "LIS": 1, "PACS": 2}
	for _, t := range byID {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		ri, ok := rank[out[i].System]
		if !ok {
			ri = 9
		}
		rj, ok := rank[out[j].System]
		if !ok {
			rj = 9
		}
		if ri != rj {
			return ri < rj
		}
		return out[i].ID < out[j].ID
	})
	return out, errs
}

// TemplateApply 套用请求。
type TemplateApply struct {
	HospitalID string            `json:"hospital_id"`
	BaselineID string            `json:"baseline_id"` // 已存在则追加，不存在则新建
	Values     map[string]string `json:"values"`      // 占位符 → 实际账号
	Skip       []int             `json:"skip"`        // 不套用的条目序号（从 0 起）
	CreatedBy  string            `json:"created_by"`
}

// ApplyBaselineTemplate 把模板（填好占位符、去掉跳过项）写入基线，返回实际新增的放行项。
func ApplyBaselineTemplate(db *sql.DB, templateID string, req TemplateApply) (added []rules.BaselineAllow, created bool, err error) {
	list, _ := ListBaselineTemplates()
	var t *BaselineTemplate
	for i := range list {
		if list[i].ID == templateID {
			t = &list[i]
		}
	}
	if t == nil {
		return nil, false, fmt.Errorf("模板 %s 不存在", templateID)
	}
	if req.HospitalID == "" || req.BaselineID == "" {
		return nil, false, fmt.Errorf("hospital_id 与 baseline_id 必填")
	}
	skip := map[int]bool{}
	for _, i := range req.Skip {
		skip[i] = true
	}
	var allows []rules.BaselineAllow
	for i, e := range t.Entries {
		if skip[i] {
			continue
		}
		for _, p := range placeholderRe.FindAllString(e.Subject, -1) {
			if strings.TrimSpace(req.Values[p]) == "" {
				return nil, false, fmt.Errorf("请填写 %s 的实际账号，或取消勾选该条", p)
			}
		}
		subject := placeholderRe.ReplaceAllStringFunc(e.Subject, func(p string) string {
			return strings.TrimSpace(req.Values[p])
		})
		allows = append(allows, rules.BaselineAllow{
			Subject: subject, Kind: e.Kind, Value: e.Value, Scope: e.Scope,
			Reason: "模板「" + t.Name + "」：" + e.Reason,
		})
	}
	if len(allows) == 0 {
		return nil, false, fmt.Errorf("没有要套用的条目")
	}
	var target, hosp string
	err = db.QueryRow(`SELECT target, hospital_id FROM baselines WHERE id = ?`, req.BaselineID).Scan(&target, &hosp)
	switch {
	case err == sql.ErrNoRows:
		if err := CreateBaseline(db, req.BaselineID, req.HospitalID, t.Target, dedupeAllows(allows), req.CreatedBy); err != nil {
			return nil, false, err
		}
		return dedupeAllows(allows), true, nil
	case err != nil:
		return nil, false, err
	}
	if hosp != req.HospitalID {
		return nil, false, fmt.Errorf("基线 %s 属于医院 %s，不能套到 %s", req.BaselineID, hosp, req.HospitalID)
	}
	if target != "" && target != t.Target {
		return nil, false, fmt.Errorf("基线 %s 的目标是 %s，模板目标是 %s，请换一个基线 ID", req.BaselineID, target, t.Target)
	}
	added, err = AddBaselineAllows(db, req.BaselineID, allows)
	return added, false, err
}

// ReevaluateLatest 用本院全部基线重评该医院某类对象的最新事实包，返回重评包数。
func ReevaluateLatest(db *sql.DB, reg *rules.Registry, hospitalID, kind string) (int, error) {
	rows, err := db.Query(`SELECT (SELECT b.id FROM fact_bundles b WHERE b.asset_id = a.id ORDER BY b.imported_at DESC, b.rowid DESC LIMIT 1)
		FROM assets a WHERE a.hospital_id = ? AND a.kind = ?`, hospitalID, kind)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id sql.NullString
		if rows.Scan(&id) == nil && id.Valid {
			ids = append(ids, id.String)
		}
	}
	rows.Close()
	for _, id := range ids {
		if _, err := EvaluateBundleAuto(db, reg, id, "", false); err != nil {
			return 0, fmt.Errorf("重评 %s 失败: %w", id, err)
		}
	}
	return len(ids), nil
}
