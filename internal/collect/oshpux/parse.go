package oshpux

import (
	"fmt"
	"strconv"
	"strings"

	"medaudit/internal/facts"
)

type getter func(key string) (string, error)
type idGen func(prefix string) string
type receiptFn func(tid, status string, rows int, stage string)

// ---------- identity ----------

type hpuxUser struct {
	name, pwdField, uid, gid, home, shell string
}

func pwdClass(field string) string {
	switch {
	case field == "x":
		return "x"
	case field == "*" || field == "!" || strings.HasPrefix(field, "!"):
		return "locked"
	case field == "":
		return "empty"
	default:
		return "hash"
	}
}

func parsePasswd(out string) []hpuxUser {
	var users []hpuxUser
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		users = append(users, hpuxUser{f[0], f[1], f[2], f[3], f[5], f[6]})
	}
	return users
}

func collectIdentity(b *facts.FactBundle, get getter, nextID idGen, rc receiptFn) {
	passwdOut, perr := get("passwd")
	groupOut, gerr := get("group")
	if perr != nil && passwdOut == "" {
		rc("hpux.identity", "failed", 0, "passwd")
		return
	}
	users := parsePasswd(passwdOut)
	groups := map[string]string{} // gid -> name
	members := map[string][]string{}
	for _, line := range strings.Split(groupOut, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), ":")
		if len(f) < 4 {
			continue
		}
		groups[f[2]] = f[0]
		if f[3] != "" {
			members[f[0]] = strings.Split(f[3], ",")
		}
	}
	rows := 0
	for _, u := range users {
		b.Facts = append(b.Facts, facts.Fact{
			FactID: nextID("identity"), Kind: facts.FactIdentity, Subject: u.name,
			Status: facts.StatusObserved, Source: "hpux.identity",
			Attributes: map[string]string{
				"uid": u.uid, "gid": u.gid, "home": u.home, "shell": u.shell,
				"pwd": pwdClass(u.pwdField),
			},
		})
		rows++
		if gname, ok := groups[u.gid]; ok {
			b.Facts = append(b.Facts, facts.Fact{
				FactID: nextID("edge"), Kind: facts.FactRoleEdge, Subject: u.name,
				Status: facts.StatusObserved, Source: "hpux.identity",
				Attributes: map[string]string{"group": gname, "gid": u.gid, "primary": "true"},
			})
			rows++
		}
	}
	for gname, ms := range members {
		for _, m := range ms {
			if m == "" {
				continue
			}
			b.Facts = append(b.Facts, facts.Fact{
				FactID: nextID("edge"), Kind: facts.FactRoleEdge, Subject: m,
				Status: facts.StatusObserved, Source: "hpux.identity",
				Attributes: map[string]string{"group": gname, "primary": "false"},
			})
			rows++
		}
	}
	// swlist 摘要（仅留存，不做漏洞判定）
	if sw, err := get("swlist"); err == nil && sw != "" {
		n := 0
		for _, line := range strings.Split(sw, "\n") {
			t := strings.TrimSpace(line)
			if t != "" && !strings.HasPrefix(t, "#") {
				n++
			}
		}
		b.Facts = append(b.Facts, facts.Fact{
			FactID: nextID("swlist"), Kind: facts.FactAccountConfig, Subject: "hpux:swlist",
			Status: facts.StatusObserved, Source: "hpux.identity",
			Attributes: map[string]string{"bundle_lines": strconv.Itoa(n)},
		})
		rows++
	}
	status := "ok"
	if gerr != nil && groupOut == "" {
		status = "partial"
	}
	rc("hpux.identity", status, rows, "")
}

// ---------- auth_policy ----------

func lsEntryPresent(out, path string) bool {
	for _, line := range strings.Split(out, "\n") {
		f := splitFields(line)
		if len(f) >= 2 && (f[0][0] == '-' || f[0][0] == 'd') && f[len(f)-1] == path {
			return true
		}
	}
	return false
}

func collectAuthPolicy(b *facts.FactBundle, get getter, nextID idGen, rc receiptFn) {
	probeOut, probeErr := get("storeprobe")
	if probeErr != nil && probeOut == "" {
		rc("hpux.auth_policy", "failed", 0, "storeprobe")
		return
	}
	shadow := lsEntryPresent(probeOut, "/etc/shadow")
	tcb := lsEntryPresent(probeOut, "/tcb")
	mode := "standard"
	if tcb {
		mode = "trusted"
	} else if shadow {
		mode = "shadow"
	}
	attrs := map[string]string{
		"mode": mode,
		"shadow_present": strconv.FormatBool(shadow),
		"tcb_present":    strconv.FormatBool(tcb),
	}
	status := "ok"
	if secOut, err := get("security"); err == nil {
		for _, line := range strings.Split(secOut, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			switch strings.TrimSpace(k) {
			case "MIN_PASSWORD_LENGTH":
				attrs["pwd_min_length"] = strings.TrimSpace(v)
			case "PASSWORD_HISTORY_DEPTH":
				attrs["pwd_history_depth"] = strings.TrimSpace(v)
			}
		}
	} else {
		status = "partial"
	}
	if kcOut, err := get("kctune"); err == nil {
		for _, line := range strings.Split(kcOut, "\n") {
			f := splitFields(line)
			if len(f) >= 2 && f[0] == "executable_stack" {
				attrs["executable_stack"] = f[1]
			}
		}
	}
	b.Facts = append(b.Facts, facts.Fact{
		FactID: nextID("authpolicy"), Kind: facts.FactAccountConfig, Subject: "hpux:password-store",
		Status: facts.StatusObserved, Source: "hpux.auth_policy", Attributes: attrs,
	})
	rc("hpux.auth_policy", status, 1, "")
}

// ---------- sudo_rbac ----------

var sudoTags = []string{"NOPASSWD:", "PASSWD:", "SETENV:", "NOSETENV:", "NOEXEC:", "EXEC:", "MAIL:", "NOMAIL:", "FOLLOW:", "NOFOLLOW:", "INTERCEPT:", "NOINTERCEPT:", "LOG_INPUT:", "LOG_OUTPUT:"}

func parseSudoLine(line string) (who, runas string, nopasswd, all bool, commands string, ok bool) {
	eq := strings.Index(line, "=")
	if eq < 0 {
		return "", "", false, false, "", false
	}
	lhs := splitFields(line[:eq])
	if len(lhs) == 0 {
		return "", "", false, false, "", false
	}
	// sudoers 规格：<主体...> <主机> = … —— 末 token 是主机规格，
	// 其前为授权主体（单主体或逗号分隔列表）。
	if len(lhs) >= 2 {
		who = strings.Join(lhs[:len(lhs)-1], " ")
	} else {
		who = lhs[0]
	}
	who = strings.TrimSpace(strings.TrimSuffix(who, ","))
	for _, part := range strings.Split(who, ",") {
		if !validSudoWho(strings.TrimSpace(part)) {
			return "", "", false, false, "", false
		}
	}
	rhs := strings.TrimSpace(line[eq+1:])
	runas = "root"
	if strings.HasPrefix(rhs, "(") {
		if end := strings.Index(rhs, ")"); end > 0 {
			inner := rhs[1:end]
			if i := strings.IndexAny(inner, ":,"); i >= 0 {
				inner = inner[:i]
			}
			runas = strings.TrimSpace(inner)
			rhs = strings.TrimSpace(rhs[end+1:])
		}
	}
	nopasswd = strings.Contains(rhs, "NOPASSWD:")
	for _, t := range sudoTags {
		rhs = strings.ReplaceAll(rhs, t, " ")
	}
	commands = strings.TrimSpace(strings.Join(splitFields(rhs), " "))
	all = commands == "ALL"
	return who, runas, nopasswd, all, commands, true
}

func validSudoWho(w string) bool {
	if w == "" {
		return false
	}
	for _, c := range w {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '%' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func collectSudoRbac(b *facts.FactBundle, get getter, nextID idGen, rc receiptFn) {
	out, _ := get("sudoers")
	rows := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Defaults") ||
			strings.Contains(line, "_Alias") {
			continue
		}
		who, runas, nopasswd, all, commands, ok := parseSudoLine(line)
		if !ok || who == "root" {
			continue
		}
		np := ""
		if nopasswd {
			np = "true"
		}
		ca := ""
		if all {
			ca = "true"
		}
		b.Facts = append(b.Facts, facts.Fact{
			FactID: nextID("sudo"), Kind: facts.FactAccountConfig, Subject: who,
			Status: facts.StatusObserved, Source: "hpux.sudo_rbac",
			Attributes: map[string]string{
				"runas": runas, "nopasswd": np, "commands_all": ca,
				"commands": commands, "file": "sudoers",
			},
		})
		rows++
	}
	if rows == 0 {
		// 无非 root 授权：仍落标记事实（区分「模板未跑」与「跑过无授权」），
		// present 反映 sudoers 是否存在（仅 root 授权时为 true）。
		b.Facts = append(b.Facts, facts.Fact{
			FactID: nextID("sudo"), Kind: facts.FactAccountConfig, Subject: "hpux:sudo",
			Status: facts.StatusObserved, Source: "hpux.sudo_rbac",
			Attributes: map[string]string{
				"sudoers_present": strconv.FormatBool(strings.TrimSpace(out) != ""),
				"grants":           "0",
			},
		})
		rows = 1
	}
	if rbacOut, err := get("rbac"); err == nil && strings.TrimSpace(rbacOut) != "" {
		b.Facts = append(b.Facts, facts.Fact{
			FactID: nextID("rbac"), Kind: facts.FactAccountConfig, Subject: "hpux:rbac",
			Status: facts.StatusObserved, Source: "hpux.sudo_rbac",
			Attributes: map[string]string{"present": "true"},
		})
		rows++
	}
	rc("hpux.sudo_rbac", "ok", rows, "")
}

// ---------- inetd ----------

func collectInetd(b *facts.FactBundle, get getter, nextID idGen, rc receiptFn) {
	out, err := get("inetdconf")
	if err != nil && out == "" {
		rc("hpux.inetd", "failed", 0, "inetdconf")
		return
	}
	rows := 0
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := splitFields(t)
		if len(f) < 6 {
			continue
		}
		b.Facts = append(b.Facts, facts.Fact{
			FactID: nextID("inetd"), Kind: facts.FactServiceConfig, Subject: f[0],
			Status: facts.StatusObserved, Source: "hpux.inetd",
			Attributes: map[string]string{
				"socket_type": f[1], "protocol": f[2], "wait": f[3],
				"user": f[4], "server": f[5],
			},
		})
		rows++
	}
	if rows == 0 {
		b.Facts = append(b.Facts, facts.Fact{
			FactID: nextID("inetd"), Kind: facts.FactServiceConfig, Subject: "hpux:inetd",
			Status: facts.StatusObserved, Source: "hpux.inetd",
			Attributes: map[string]string{"present": "true", "services": "0"},
		})
		rows = 1
	}
	rc("hpux.inetd", "ok", rows, "")
}

// ---------- ls -ld 解析（startup_perm / setuid 共用） ----------

type lsEntry struct {
	path, owner, modeOctal     string
	wOther, wGroup, suid, sgid bool
	isDir                      bool
}

func parseLsLine(line string) (lsEntry, bool) {
	f := splitFields(line)
	if len(f) < 9 {
		return lsEntry{}, false
	}
	m := f[0]
	if len(m) != 10 || (m[0] != '-' && m[0] != 'd' && m[0] != 'l') {
		return lsEntry{}, false
	}
	path := strings.Join(f[8:], " ")
	if i := strings.Index(path, " -> "); i >= 0 {
		path = path[:i]
	}
	perm := func(tri string) int {
		v := 0
		if tri[0] == 'r' {
			v += 4
		}
		if tri[1] == 'w' {
			v += 2
		}
		if tri[2] == 'x' || tri[2] == 's' || tri[2] == 't' {
			v += 1
		}
		return v
	}
	oct := perm(m[1:4])*64 + perm(m[4:7])*8 + perm(m[7:10])
	suid := m[3] == 's' || m[3] == 'S'
	sgid := m[6] == 's' || m[6] == 'S'
	if suid {
		oct += 04000
	}
	if sgid {
		oct += 02000
	}
	if m[9] == 't' || m[9] == 'T' {
		oct += 01000
	}
	return lsEntry{
		path: path, owner: f[2], modeOctal: fmt.Sprintf("%04o", oct),
		wOther: m[8] == 'w', wGroup: m[5] == 'w',
		suid: suid, sgid: sgid, isDir: m[0] == 'd',
	}, true
}

func collectStartupPerm(b *facts.FactBundle, get getter, nextID idGen, rc receiptFn) {
	out, err := get("startupls")
	if err != nil && out == "" {
		rc("hpux.startup_perm", "failed", 0, "startupls")
		return
	}
	rows := 0
	for _, line := range strings.Split(out, "\n") {
		e, ok := parseLsLine(line)
		if !ok {
			continue
		}
		// 跳过符号链接本体（其权限无关，目标文件自有条目）
		if strings.HasPrefix(line, "l") {
			continue
		}
		b.Facts = append(b.Facts, facts.Fact{
			FactID: nextID("startup") + "-d0", Kind: facts.FactFilePerm, Subject: e.path,
			Status: facts.StatusObserved, Source: "hpux.startup_perm",
			Attributes: map[string]string{
				"path": e.path, "mode": e.modeOctal, "owner": e.owner,
				"writable_by_other": strconv.FormatBool(e.wOther),
				"writable_by_group": strconv.FormatBool(e.wGroup),
			},
		})
		rows++
	}
	rc("hpux.startup_perm", "ok", rows, "")
}

func collectSetuid(b *facts.FactBundle, get getter, nextID idGen, rc receiptFn) {
	out, err := get("setuidls")
	if err != nil && out == "" {
		rc("hpux.setuid_files", "failed", 0, "setuidls")
		return
	}
	rows := 0
	for _, line := range strings.Split(out, "\n") {
		e, ok := parseLsLine(line)
		if !ok || strings.HasPrefix(line, "l") || strings.HasPrefix(line, "d") {
			continue
		}
		b.Facts = append(b.Facts, facts.Fact{
			FactID: nextID("setuid"), Kind: facts.FactFilePerm, Subject: e.path,
			Status: facts.StatusObserved, Source: "hpux.setuid_files",
			Attributes: map[string]string{
				"path": e.path, "mode": e.modeOctal, "owner": e.owner,
				"setuid": strconv.FormatBool(e.suid), "setgid": strconv.FormatBool(e.sgid),
			},
		})
		rows++
	}
	if rows == 0 {
		b.Facts = append(b.Facts, facts.Fact{
			FactID: nextID("setuid"), Kind: facts.FactFilePerm, Subject: "hpux:setuid-scan",
			Status: facts.StatusObserved, Source: "hpux.setuid_files",
			Attributes: map[string]string{"count": "0"},
		})
		rows = 1
	}
	rc("hpux.setuid_files", "ok", rows, "")
}
