package apiaudit

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Operation 一个待测端点（方法 + 路径模板）。
type Operation struct {
	Method string `json:"method"`
	Path   string `json:"path"`   // 模板形式，如 /api/users/{user_id}
	Source string `json:"source"` // openapi | har
}

var httpMethods = map[string]bool{
	"get": true, "post": true, "put": true, "patch": true,
	"delete": true, "head": true, "options": true,
}

// ---- OpenAPI 3 ----

type openAPIDoc struct {
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

// ParseOpenAPI 从 OpenAPI 3 JSON 提取操作清单。
func ParseOpenAPI(raw []byte) ([]Operation, error) {
	var doc openAPIDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("解析 OpenAPI: %w", err)
	}
	var ops []Operation
	for path, methods := range doc.Paths {
		for m := range methods {
			if !httpMethods[strings.ToLower(m)] {
				continue // parameters 等非方法键跳过
			}
			ops = append(ops, Operation{Method: strings.ToUpper(m), Path: path, Source: "openapi"})
		}
	}
	sortOps(ops)
	if len(ops) == 0 {
		return nil, fmt.Errorf("OpenAPI 中未发现任何操作")
	}
	return ops, nil
}

// ---- HAR ----

type harDoc struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method string `json:"method"`
				URL    string `json:"url"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

var (
	uuidSeg = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	numSeg  = regexp.MustCompile(`^[0-9]+$`)
)

// templatizePath 把具体路径中的数值/UUID 段替换为 {id}，得到模板路径。
func templatizePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		if numSeg.MatchString(s) || uuidSeg.MatchString(s) {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

// ParseHAR 从 HAR 提取去重后的操作清单（仅方法+路径，不使用其中的凭据头）。
func ParseHAR(raw []byte) ([]Operation, error) {
	var doc harDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("解析 HAR: %w", err)
	}
	seen := map[string]bool{}
	var ops []Operation
	for _, e := range doc.Log.Entries {
		u, err := url.Parse(e.Request.URL)
		if err != nil || u.Path == "" {
			continue
		}
		op := Operation{
			Method: strings.ToUpper(e.Request.Method),
			Path:   templatizePath(u.Path),
			Source: "har",
		}
		k := op.Method + " " + op.Path
		if seen[k] {
			continue
		}
		seen[k] = true
		ops = append(ops, op)
	}
	sortOps(ops)
	if len(ops) == 0 {
		return nil, fmt.Errorf("HAR 中未发现任何请求")
	}
	return ops, nil
}

func sortOps(ops []Operation) {
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Path != ops[j].Path {
			return ops[i].Path < ops[j].Path
		}
		return ops[i].Method < ops[j].Method
	})
}

// pathParams 提取模板路径中的参数名。
func pathParams(tmpl string) []string {
	var out []string
	for _, seg := range strings.Split(tmpl, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			out = append(out, seg[1:len(seg)-1])
		}
	}
	return out
}

// instantiate 用参数值填充模板；缺参数返回 ok=false。
func instantiate(tmpl string, vals map[string]string) (string, bool) {
	out := tmpl
	for _, p := range pathParams(tmpl) {
		v, ok := vals[p]
		if !ok || v == "" {
			return "", false
		}
		out = strings.ReplaceAll(out, "{"+p+"}", url.PathEscape(v))
	}
	return out, true
}
