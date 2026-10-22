package mw

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"medaudit/internal/facts"
)

// ---------- nginx 配置解析（子集：指令/块/引号/注释/include） ----------

type directive struct {
	Name     string
	Args     []string
	Children []directive
	Block    bool
}

func tokenizeNginx(content string) []string {
	var tokens []string
	var cur strings.Builder
	inQuote := byte(0)
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(content); i++ {
		c := content[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			} else {
				cur.WriteByte(c)
			}
			continue
		}
		switch {
		case c == '#':
			for i < len(content) && content[i] != '\n' {
				i++
			}
		case c == '"' || c == '\'':
			inQuote = c
		case c == '{' || c == '}' || c == ';':
			flush()
			tokens = append(tokens, string(c))
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return tokens
}

func parseNginxTokens(tokens []string, pos *int) []directive {
	var out []directive
	for *pos < len(tokens) {
		tok := tokens[*pos]
		if tok == "}" {
			*pos++
			return out
		}
		if tok == "{" || tok == ";" {
			*pos++
			continue
		}
		d := directive{Name: tok}
		*pos++
		for *pos < len(tokens) {
			t := tokens[*pos]
			if t == ";" {
				*pos++
				break
			}
			if t == "{" {
				*pos++
				d.Block = true
				d.Children = parseNginxTokens(tokens, pos)
				break
			}
			if t == "}" {
				break
			}
			d.Args = append(d.Args, t)
			*pos++
		}
		out = append(out, d)
	}
	return out
}

// expandIncludes 展开 include（相对路径先按主配置目录、再按 prefix 解析；缺失记 partial）。
func expandIncludes(dirs []directive, confDir, prefix string, depth int, bd *builder) []directive {
	if depth > 5 {
		return dirs
	}
	var out []directive
	for _, d := range dirs {
		if d.Name == "include" && len(d.Args) > 0 && !d.Block {
			pattern := d.Args[0]
			var matches []string
			if filepath.IsAbs(pattern) {
				matches, _ = filepath.Glob(pattern)
			} else {
				matches, _ = filepath.Glob(filepath.Join(confDir, pattern))
				if len(matches) == 0 {
					matches, _ = filepath.Glob(filepath.Join(prefix, pattern))
				}
			}
			if len(matches) == 0 {
				bd.receipt("mw.nginx.include", "partial", 0)
				continue
			}
			for _, m := range matches {
				raw, err := os.ReadFile(m)
				if err != nil {
					bd.receipt("mw.nginx.include", "partial", 0)
					continue
				}
				pos := 0
				sub := parseNginxTokens(tokenizeNginx(string(raw)), &pos)
				out = append(out, expandIncludes(sub, filepath.Dir(m), prefix, depth+1, bd)...)
			}
			continue
		}
		if d.Block {
			d.Children = expandIncludes(d.Children, confDir, prefix, depth, bd)
		}
		out = append(out, d)
	}
	return out
}

// nginxVersion 尝试运行 nginx -v 取版本（prefix/sbin/nginx 优先，其次 PATH）。
func nginxVersion(prefix string) string {
	candidates := []string{filepath.Join(prefix, "sbin", "nginx"), "nginx"}
	for _, bin := range candidates {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cmd := exec.CommandContext(ctx, bin, "-v")
		var stderr strings.Builder
		cmd.Stderr = &stderr
		_ = cmd.Run()
		cancel()
		out := stderr.String()
		if idx := strings.Index(out, "nginx/"); idx >= 0 {
			rest := out[idx+len("nginx/"):]
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				return strings.TrimRight(fields[0], " \t\r\n")
			}
		}
	}
	return ""
}

// CollectNginx 采集一个 Nginx 配置（--home 为配置目录或 nginx.conf 文件）。
func CollectNginx(opts Options) (*facts.FactBundle, error) {
	home := opts.Home
	mainConf := home
	prefix := home
	if info, err := os.Stat(home); err == nil && info.IsDir() {
		mainConf = filepath.Join(home, "nginx.conf")
		if _, err := os.Stat(mainConf); err != nil {
			alt := filepath.Join(home, "conf", "nginx.conf")
			if _, err2 := os.Stat(alt); err2 == nil {
				mainConf = alt
			} else {
				return nil, fmt.Errorf("在 %s 下找不到 nginx.conf", home)
			}
		}
	} else {
		prefix = filepath.Dir(home)
	}
	raw, err := os.ReadFile(mainConf)
	if err != nil {
		return nil, fmt.Errorf("读取主配置失败: %w", err)
	}
	started := time.Now().UTC().Truncate(time.Second)
	bd := &builder{}
	pos := 0
	tree := parseNginxTokens(tokenizeNginx(string(raw)), &pos)
	tree = expandIncludes(tree, filepath.Dir(mainConf), prefix, 0, bd)
	bd.receipt("mw.nginx.config", "ok", len(tree))

	version := nginxVersion(prefix)

	// 配置的 worker 用户（主上下文 user 指令）
	configuredUser := ""
	for _, d := range tree {
		if d.Name == "user" && len(d.Args) > 0 {
			configuredUser = d.Args[0]
		}
	}

	// 实例事实
	bd.fact(facts.FactServiceConfig, "nginx", "mw.nginx.instance", facts.StatusObserved,
		map[string]string{"version": version, "config": mainConf, "prefix": prefix, "configured_user": configuredUser})
	bd.receipt("mw.nginx.instance", "ok", 1)

	// 运行进程
	procs := findProcesses(func(cmd string) bool {
		return strings.Contains(cmd, "nginx: master process")
	})
	targetIdentity := "nginx@" + mainConf
	if len(procs) > 0 {
		p := procs[0]
		bd.fact(facts.FactProcess, "nginx", "mw.nginx.process", facts.StatusObserved,
			map[string]string{
				"pid": strconv.Itoa(p.PID), "run_user": p.User,
				"run_uid": strconv.Itoa(p.UID), "configured_user": configuredUser,
			})
		bd.receipt("mw.nginx.process", "ok", len(procs))
		if p.User != "" {
			targetIdentity = p.User + "@nginx-process"
		}
	} else {
		bd.receipt("mw.nginx.process", "partial", 0)
	}

	// 遍历 http/server/location
	counts := map[string]int{}
	var walk func(dirs []directive, ctx string, serverName string)
	walk = func(dirs []directive, ctx string, serverName string) {
		for _, d := range dirs {
			switch d.Name {
			case "server":
				name := serverNameOf(d)
				walk(d.Children, ctx+"/server", name)
			case "location":
				loc := ""
				if len(d.Args) > 0 {
					loc = d.Args[len(d.Args)-1]
				}
				walk(d.Children, ctx+"/location "+loc, serverName)
			case "listen":
				if len(d.Args) == 0 {
					continue
				}
				addr, port, ok := parseListen(d.Args[0])
				if !ok {
					continue
				}
				ssl := false
				for _, a := range d.Args[1:] {
					if a == "ssl" {
						ssl = true
					}
				}
				name := serverName
				if name == "" {
					name = "_"
				}
				bd.fact(facts.FactServiceConfig, "server:"+name+":"+port, "mw.nginx.listeners", facts.StatusObserved,
					map[string]string{
						"port": port, "address": addr, "ssl": boolStr(ssl),
						"server_name": name, "context": ctx,
					})
				counts["listeners"]++
			case "ssl_protocols":
				bd.fact(facts.FactServiceConfig, "tls:"+ctx, "mw.nginx.tls", facts.StatusObserved,
					map[string]string{"protocols": strings.Join(d.Args, " "), "context": ctx})
				counts["tls"]++
			case "autoindex":
				if len(d.Args) > 0 && d.Args[0] == "on" {
					bd.fact(facts.FactServiceConfig, "autoindex:"+ctx, "mw.nginx.autoindex", facts.StatusObserved,
						map[string]string{"context": ctx, "server_name": serverName})
					counts["autoindex"]++
				}
			case "root":
				if len(d.Args) > 0 && strings.Contains(ctx, "/server") {
					name := serverName
					if name == "" {
						name = "_"
					}
					bd.fact(facts.FactServiceConfig, "root:"+name, "mw.nginx.roots", facts.StatusObserved,
						map[string]string{"root": d.Args[0], "context": ctx})
					counts["roots"]++
				}
			default:
				if d.Block {
					walk(d.Children, ctx+"/"+d.Name, serverName)
				}
			}
		}
	}
	walk(tree, "", "")
	bd.receipt("mw.nginx.listeners", "ok", counts["listeners"])
	bd.receipt("mw.nginx.tls", "ok", counts["tls"])
	bd.receipt("mw.nginx.autoindex", "ok", counts["autoindex"])

	// 配置文件与目录权限
	pn := 0
	for _, p := range []string{mainConf, filepath.Dir(mainConf)} {
		attrs := permAttrs(p)
		if _, bad := attrs["error"]; bad {
			continue
		}
		attrs["path"] = p
		bd.fact(facts.FactFilePerm, p, "mw.nginx.config_perms", facts.StatusObserved, attrs)
		pn++
	}
	if pn < 2 {
		bd.receipt("mw.nginx.config_perms", "partial", pn)
	} else {
		bd.receipt("mw.nginx.config_perms", "ok", pn)
	}

	return newBundle(opts, facts.TargetMWNginx, "mw-nginx", targetIdentity, version, started, bd), nil
}

func serverNameOf(server directive) string {
	for _, d := range server.Children {
		if d.Name == "server_name" && len(d.Args) > 0 {
			return d.Args[0]
		}
	}
	return ""
}

// parseListen 解析 listen 的地址参数：80 / 127.0.0.1:8080 / [::]:443 / unix:...（跳过）。
func parseListen(arg string) (addr, port string, ok bool) {
	if strings.HasPrefix(arg, "unix:") {
		return "", "", false
	}
	if strings.HasPrefix(arg, "[") {
		end := strings.Index(arg, "]")
		if end < 0 {
			return "", "", false
		}
		addr = arg[1:end]
		rest := arg[end+1:]
		if strings.HasPrefix(rest, ":") {
			return addr, rest[1:], true
		}
		return addr, "", false
	}
	if idx := strings.LastIndex(arg, ":"); idx >= 0 {
		return arg[:idx], arg[idx+1:], true
	}
	return "", arg, true
}
