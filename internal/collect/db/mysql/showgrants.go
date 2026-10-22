package mysql

import (
	"fmt"
	"strings"
)

// ParsedGrant 是 SHOW GRANTS 单条语句的语义解析结果。
// 不靠搜索 "ALL PRIVILEGES" 文本判定权限：privs 按原文 token 记录，
// 作用域结构化，展开语义留给规则引擎按产品版本处理。
// partial revokes 表现为 REVOKE ... FROM 语句，IsRevoke=true。
type ParsedGrant struct {
	GranteeUser     string
	GranteeHost     string
	IsRoleGrant     bool
	IsRevoke        bool
	Roles           []RoleRef // IsRoleGrant=true 时
	Privs           []string  // 权限 token 原文，如 SELECT、ALL PRIVILEGES、USAGE
	Scope           string    // "*.*"、"db.*"`、`"db"."tbl"`
	WithGrantOption bool
}

type RoleRef struct {
	User string
	Host string
}

func (r RoleRef) String() string { return r.User + "@" + r.Host }

// ParseShowGrant 解析单条 GRANT/REVOKE 语句。支持：
//  1. GRANT <privs> ON <scope> TO 'u'@'h' [WITH GRANT OPTION]
//  2. GRANT 'r1'@'h1', 'r2'@'h2' TO 'u'@'h' [WITH ADMIN OPTION]（角色授予，无 ON 子句）
//  3. REVOKE <privs> ON <scope> FROM 'u'@'h'（partial revokes 表现为此类语句）
//
// 账号可用单引号或反引号引用。
func ParseShowGrant(stmt string) (*ParsedGrant, error) {
	s := strings.TrimSpace(stmt)
	upper := strings.ToUpper(s)
	g := &ParsedGrant{}
	var rest string
	switch {
	case strings.HasPrefix(upper, "GRANT "):
		rest = strings.TrimSpace(s[len("GRANT "):])
	case strings.HasPrefix(upper, "REVOKE "):
		g.IsRevoke = true
		rest = strings.TrimSpace(s[len("REVOKE "):])
	default:
		return nil, fmt.Errorf("not a GRANT/REVOKE statement: %q", trunc(stmt, 60))
	}

	// 切出 " TO " / " FROM "（最后一个，作为分隔被授予者）。
	sep := " TO "
	if g.IsRevoke {
		sep = " FROM "
	}
	idx := strings.LastIndex(strings.ToUpper(rest), sep)
	if idx < 0 {
		return nil, fmt.Errorf("missing %s clause: %q", strings.TrimSpace(sep), trunc(stmt, 60))
	}
	head := strings.TrimSpace(rest[:idx])
	tail := strings.TrimSpace(rest[idx+len(sep):])
	// tail: 'u'@'h' [WITH ...]
	grantee, trailing, err := splitAccount(strings.TrimSpace(tail))
	if err != nil {
		return nil, fmt.Errorf("bad grantee %q: %w", trunc(tail, 40), err)
	}
	g.GranteeUser, g.GranteeHost = grantee.User, grantee.Host
	upTrail := strings.ToUpper(trailing)
	if strings.Contains(upTrail, "WITH GRANT OPTION") {
		g.WithGrantOption = true
	}

	// head 无 ON → 角色授予（REVOKE 无 ON 时视为撤销全部，按 *.* 处理）。
	if !containsWordTopLevel(head, "ON") {
		if g.IsRevoke {
			for _, p := range splitTopLevel(head, ',') {
				p = strings.TrimSpace(p)
				if p != "" {
					g.Privs = append(g.Privs, p)
				}
			}
			g.Scope = "*.*"
			return g, nil
		}
		roles, err := parseRoleList(head)
		if err != nil {
			return nil, err
		}
		g.IsRoleGrant = true
		g.Roles = roles
		return g, nil
	}
	// 有 ON：privs ON scope
	onIdx := indexWordTopLevel(head, "ON")
	privPart := strings.TrimSpace(head[:onIdx])
	scopePart := strings.TrimSpace(head[onIdx+len("ON"):])
	g.Scope = normalizeScope(scopePart)
	for _, p := range splitTopLevel(privPart, ',') {
		p = strings.TrimSpace(p)
		if p != "" {
			g.Privs = append(g.Privs, p)
		}
	}
	return g, nil
}

// splitAccount 解析 "'u'@'h'"（单引号或反引号），返回账号与剩余后缀。
func splitAccount(s string) (RoleRef, string, error) {
	var r RoleRef
	s = strings.TrimSpace(s)
	qc, ok := quoteChar(s)
	if !ok {
		return r, "", fmt.Errorf("expected quoted user")
	}
	user, rest, err := readQuoted(s, qc)
	if err != nil {
		return r, "", err
	}
	r.User = user
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, "@") {
		return r, "", fmt.Errorf("expected @host")
	}
	rest = strings.TrimSpace(rest[1:])
	if qc2, ok := quoteChar(rest); ok {
		host, rest2, err := readQuoted(rest, qc2)
		if err != nil {
			return r, "", err
		}
		r.Host = host
		return r, strings.TrimSpace(rest2), nil
	}
	// 裸主机名（如少见写法），取到空白为止。
	end := strings.IndexAny(rest, " \t")
	if end < 0 {
		r.Host = rest
		return r, "", nil
	}
	r.Host = rest[:end]
	return r, strings.TrimSpace(rest[end:]), nil
}

func quoteChar(s string) (byte, bool) {
	if s == "" {
		return 0, false
	}
	if s[0] == '\'' || s[0] == '`' {
		return s[0], true
	}
	return 0, false
}

// readQuoted 读一个引号字符串，处理转义（” 或 “）。
func readQuoted(s string, qc byte) (string, string, error) {
	var b strings.Builder
	i := 1
	for i < len(s) {
		c := s[i]
		if c == qc {
			if i+1 < len(s) && s[i+1] == qc {
				b.WriteByte(qc)
				i += 2
				continue
			}
			return b.String(), s[i+1:], nil
		}
		b.WriteByte(c)
		i++
	}
	return "", "", fmt.Errorf("unterminated quoted string")
}

func parseRoleList(s string) ([]RoleRef, error) {
	var out []RoleRef
	for _, part := range splitTopLevel(s, ',') {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		r, trailing, err := splitAccount(part)
		if err != nil {
			return nil, fmt.Errorf("bad role %q: %w", trunc(part, 40), err)
		}
		if strings.TrimSpace(trailing) != "" {
			return nil, fmt.Errorf("unexpected trailing %q in role list", trunc(trailing, 30))
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty role list")
	}
	return out, nil
}

// normalizeScope 规范化作用域：去反引号，保留 * 语义。
func normalizeScope(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "`", "")
	// 形如 db.* / *.* / db.tbl
	return s
}

// splitTopLevel 按分隔符切分，忽略引号（单引号/反引号）内的分隔符。
func splitTopLevel(s string, sep byte) []string {
	var out []string
	var b strings.Builder
	var qc byte // 当前引号字符，0 表示不在引号内
	for i := 0; i < len(s); i++ {
		c := s[i]
		if qc != 0 {
			if c == qc {
				if i+1 < len(s) && s[i+1] == qc {
					b.WriteByte(c)
					b.WriteByte(s[i+1])
					i++
					continue
				}
				qc = 0
			}
			b.WriteByte(c)
			continue
		}
		if c == '\'' || c == '`' {
			qc = c
			b.WriteByte(c)
			continue
		}
		if c == sep {
			out = append(out, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	out = append(out, b.String())
	return out
}

// containsWordTopLevel / indexWordTopLevel：在引号外层查找独立单词。
func containsWordTopLevel(s, word string) bool { return indexWordTopLevel(s, word) >= 0 }

func indexWordTopLevel(s, word string) int {
	upper := strings.ToUpper(s)
	uw := strings.ToUpper(word)
	var qc byte
	for i := 0; i+len(uw) <= len(s); i++ {
		c := s[i]
		if qc != 0 {
			if c == qc {
				if i+1 < len(s) && s[i+1] == qc {
					i++ // 转义，不退出引号
				} else {
					qc = 0
				}
			}
			continue
		}
		if c == '\'' || c == '`' {
			qc = c
			continue
		}
		if upper[i:i+len(uw)] == uw {
			before := i == 0 || !isWordChar(s[i-1])
			after := i+len(uw) == len(s) || !isWordChar(s[i+len(uw)])
			if before && after {
				return i
			}
		}
	}
	return -1
}

func isWordChar(c byte) bool {
	return c == '_' || c == '$' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
