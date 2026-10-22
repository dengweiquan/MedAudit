// Package mysql 模板注册表：解析 queries/mysql/*.sql 的头部注释，
// 注册模板 ID、版本、最小权限声明。SQL 语句只读固定，参数仅允许白名单替换。
package mysql

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Template 版本化采集模板。
type Template struct {
	ID          string
	Version     string
	MinPrivs    string
	Description string
	Params      []string // 需调用方提供的参数名，如 DB
	SQL         string
	// Dynamic 为 true 时 SQL 由代码按固定形状生成（如 SHOW GRANTS），不来自文件。
	Dynamic bool
}

// LoadTemplates 从 queries/mysql/*.sql 加载模板，按文件名排序。
// 另注册动态模板 mysql.show_grants（逐账号 SHOW GRANTS，固定语句形状）。
func LoadTemplates() ([]Template, error) {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "queries", "mysql")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read templates dir %s: %w", dir, err)
	}
	var out []Template
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		t, err := parseTemplateFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	// 动态模板：SHOW GRANTS（语义解析，非文本搜索）。
	out = append(out, Template{
		ID:          "mysql.show_grants",
		Version:     "1",
		MinPrivs:    "SHOW GRANTS FOR <account>（需对目标账号的 GRANT OPTION 或全局权限）",
		Description: "逐账号 SHOW GRANTS，按语义解析为权限/角色事实；不靠搜索 ALL PRIVILEGES 文本判定。",
		Dynamic:     true,
	})
	return out, nil
}

func parseTemplateFile(path string) (Template, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Template{}, err
	}
	t := Template{}
	var sqlLines []string
	for _, line := range strings.Split(string(raw), "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "--") {
			body := strings.TrimSpace(strings.TrimPrefix(trim, "--"))
			switch {
			case strings.HasPrefix(body, "template:"):
				t.ID = strings.TrimSpace(strings.TrimPrefix(body, "template:"))
			case strings.HasPrefix(body, "version:"):
				t.Version = strings.TrimSpace(strings.TrimPrefix(body, "version:"))
			case strings.HasPrefix(body, "min_privileges:"):
				t.MinPrivs = strings.TrimSpace(strings.TrimPrefix(body, "min_privileges:"))
			case strings.HasPrefix(body, "description:"):
				t.Description = strings.TrimSpace(strings.TrimPrefix(body, "description:"))
			case strings.HasPrefix(body, "params:"):
				for _, p := range strings.Split(strings.TrimSpace(strings.TrimPrefix(body, "params:")), ",") {
					p = strings.TrimSpace(p)
					if i := strings.Index(p, " "); i > 0 {
						p = p[:i]
					}
					if p != "" {
						t.Params = append(t.Params, p)
					}
				}
			}
			continue
		}
		sqlLines = append(sqlLines, line)
	}
	t.SQL = strings.TrimSpace(strings.Join(sqlLines, "\n"))
	if t.ID == "" || t.Version == "" || t.SQL == "" {
		return Template{}, fmt.Errorf("template file %s missing id/version/sql", path)
	}
	lower := strings.ToLower(t.SQL)
	for _, kw := range []string{"insert ", "update ", "delete ", "create ", "drop ", "alter ", "grant ", "revoke ", "truncate "} {
		// 模板只允许 SELECT（注释行已剥离）。
		for _, l := range strings.Split(lower, "\n") {
			ls := strings.TrimSpace(l)
			if strings.HasPrefix(ls, kw) {
				return Template{}, fmt.Errorf("template %s: non-SELECT statement not allowed", t.ID)
			}
		}
	}
	return t, nil
}
