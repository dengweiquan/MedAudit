package linux

import (
	"fmt"
	"path/filepath"
	"strings"
)

// OratabEntry /etc/oratab 的一行：SID:ORACLE_HOME。
type OratabEntry struct {
	SID  string
	Home string
}

// ParseOratab 解析 oratab 文本：跳过注释（#）与空行、格式错误的行；
// 第三列（Y/N，是否自启）与本采集无关，不解析。
func ParseOratab(data []byte) []OratabEntry {
	var out []OratabEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		sid := strings.TrimSpace(parts[0])
		home := strings.TrimSpace(parts[1])
		if sid == "" || home == "" {
			continue
		}
		out = append(out, OratabEntry{SID: sid, Home: home})
	}
	return out
}

// LocateSqlnetOra 定位某 Home 的 sqlnet.ora：
// tnsAdmin 非空时取 <tnsAdmin>/sqlnet.ora，否则取 <home>/network/admin/sqlnet.ora。
// 注意：tnsAdmin 必须是实例级 TNS_ADMIN（可靠已知时才传）；绝不传采集器自身环境的 TNS_ADMIN。
func LocateSqlnetOra(home, tnsAdmin string) string {
	if tnsAdmin != "" {
		return filepath.Join(tnsAdmin, "sqlnet.ora")
	}
	return filepath.Join(home, "network", "admin", "sqlnet.ora")
}

// ParseSqlnetOra 解析 sqlnet.ora 文本：返回参数（键大写）与 IFILE 链（按出现顺序）。
// 行格式为 KEY = value；# 开头为注释；值去首尾空白与首尾引号；键大小写不敏感。
// 同一参数后出现的值覆盖先前值；IFILE 本身不进参数表。
func ParseSqlnetOra(data []byte) (params map[string]string, ifiles []string) {
	params = map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToUpper(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		if k == "" {
			continue
		}
		if k == "IFILE" {
			ifiles = append(ifiles, v)
			continue
		}
		params[k] = v
	}
	return params, ifiles
}

// SqlnetMaxIFILEDepth IFILE 递归跟随深度上限。
const SqlnetMaxIFILEDepth = 10

// ResolveSqlnetOra 从 startPath 起解析 sqlnet.ora 并跟随 IFILE 链。
// 返回合并后的参数（后出现覆盖先前）与按读取顺序的文件链。
// 相对 IFILE 路径按包含文件所在目录解析；环（已访路径）与超深时返回错误，
// 调用方不得用部分参数下结论。
func ResolveSqlnetOra(readFile func(path string) ([]byte, error), startPath string) (map[string]string, []string, error) {
	params := map[string]string{}
	var chain []string
	visited := map[string]bool{}
	var walk func(path string, depth int) error
	walk = func(path string, depth int) error {
		if depth > SqlnetMaxIFILEDepth {
			return fmt.Errorf("IFILE 递归超深（上限 %d）：%s", SqlnetMaxIFILEDepth, path)
		}
		clean := filepath.Clean(path)
		if visited[clean] {
			return fmt.Errorf("IFILE 环：%s 已解析过", clean)
		}
		visited[clean] = true
		data, err := readFile(clean)
		if err != nil {
			return err
		}
		chain = append(chain, clean)
		ps, ifs := ParseSqlnetOra(data)
		for k, v := range ps {
			params[k] = v
		}
		for _, f := range ifs {
			if !filepath.IsAbs(f) {
				f = filepath.Join(filepath.Dir(clean), f)
			}
			if err := walk(f, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(startPath, 0); err != nil {
		return nil, nil, err
	}
	return params, chain, nil
}
