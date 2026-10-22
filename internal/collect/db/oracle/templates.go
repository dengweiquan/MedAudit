// Package oracle 模板注册表：解析 queries/oracle/*.sql 的头部注释。
// 本包需要 CGO + Oracle Instant Client（见 prototype.go 头部注释）。
package oracle

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
	SQL         string
}

// LoadTemplates 从 queries/oracle/*.sql 加载模板，按文件名排序。
func LoadTemplates() ([]Template, error) {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "queries", "oracle")
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
	for _, l := range strings.Split(lower, "\n") {
		ls := strings.TrimSpace(l)
		for _, kw := range []string{"insert ", "update ", "delete ", "create ", "drop ", "alter ", "grant ", "revoke ", "truncate "} {
			if strings.HasPrefix(ls, kw) {
				return Template{}, fmt.Errorf("template %s: non-SELECT statement not allowed", t.ID)
			}
		}
	}
	return t, nil
}
