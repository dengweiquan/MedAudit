package remediation

import (
	"fmt"
	"strconv"
	"strings"

	"medaudit/internal/facts"
)

func init() {
	generators["os.linux.sudo_nopasswd_all"] = linuxSudo(true)
	generators["os.linux.sudo_all"] = linuxSudo(false)
	generators["os.linux.root_mismatch"] = linuxRootMismatch
	generators["os.linux.high_capabilities"] = linuxHighCaps
	generators["os.linux.writable_service_file"] = linuxWritableFile
}

// linuxSudo sudoers 行级处置：先整文件备份，再按行号精确定位编辑，visudo 校验；
// 回滚 = 备份文件整份还原（sudoers 误改会锁死 sudo，必须备份先行）。
func linuxSudo(nopasswd bool) generator {
	ruleID := "os.linux.sudo_all"
	action := "整行注释停用"
	if nopasswd {
		ruleID = "os.linux.sudo_nopasswd_all"
		action = "去掉 NOPASSWD（保留 sudo 但须输口令）"
	}
	return func(subject string, ev []facts.Fact) *Script {
		f := firstFact(ev, "linux.sudo")
		if f == nil {
			return nil
		}
		file := f.Attributes["file"]
		raw := f.Attributes["raw"]
		if file == "" || raw == "" {
			return nil
		}
		bak := file + ".m15-rollback"
		var edit string
		if nopasswd {
			edit = fmt.Sprintf("sed -i \"${L}s/NOPASSWD:[[:space:]]*//\" %s", file)
		} else {
			edit = fmt.Sprintf("sed -i \"${L}s/^/# M15-REVOKED /\" %s", file)
		}
		fix := strings.Join([]string{
			fmt.Sprintf("cp -a %s %s", file, bak),
			fmt.Sprintf("L=$(grep -nF %s %s | cut -d: -f1)", sq(raw), file),
			edit,
			fmt.Sprintf("visudo -cf %s", file),
		}, "\n")
		return &Script{
			RuleID: ruleID, Subject: subject, Scope: file,
			Precheck: fmt.Sprintf("grep -nF %s %s; sudo -l -U %s 2>/dev/null | head -5", sq(raw), file, strings.TrimPrefix(subject, "%")),
			Fix:      fix,
			Verify:   fmt.Sprintf("grep -nF %s %s; echo ---; sudo -l -U %s 2>/dev/null | head -5", sq(raw), file, strings.TrimPrefix(subject, "%")),
			Rollback: fmt.Sprintf("cp -a %s %s\nvisudo -cf %s", bak, file, file),
			Note:     "处置方式：" + action + "。sudoers 语法错误会导致 sudo 整体不可用——编辑后必须 visudo 校验通过；另开 root 会话再执行更稳妥。主体为 %组 时 Verify 的 sudo -l 需用组内真实用户复核。",
		}
	}
}

func linuxRootMismatch(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "linux.proc_scan")
	if f == nil {
		return nil
	}
	cfgUser := f.Attributes["configured_user"]
	comm := f.Attributes["comm"]
	exe := f.Attributes["exe"]
	unitRef := "<单元>"
	if u := f.Attributes["unit"]; u != "" {
		unitRef = u
	}
	precheck := fmt.Sprintf("ps -eo user,euid,comm,args | grep -F %s | grep -v grep; systemctl list-units --type=service | grep -i %s", sq(comm), comm)
	if unitRef != "<单元>" {
		precheck = fmt.Sprintf("systemctl cat %s; systemctl show %s -p User,MainPID; ps -eo user,euid,comm,args | grep -F %s | grep -v grep", unitRef, unitRef, sq(comm))
	}
	return &Script{
		RuleID: "os.linux.root_mismatch", Subject: subject,
		Precheck: precheck,
		Fix: "-- 指导型整改：单元配置用户为 " + cfgUser + "，进程实际 EUID=0，两条对齐路径二选一（单元：" + unitRef + "，systemctl cat " + unitRef + "）：\n" +
			"-- (a) 让服务真正以配置用户运行（推荐）：确认二进制与数据目录属主允许 " + cfgUser + " 读写后，检查单元是否被 override/启动脚本以 root 拉起并修正，然后 systemctl daemon-reload && systemctl restart " + unitRef + "；\n" +
			"-- (b) 若业务确需 root 运行：把单元 User= 改为 root 使配置与实际一致，并将本项走基线备案说明理由。\n" +
			"-- 进程：" + comm + "（" + exe + "）",
		Verify:   "ps -eo user,euid,comm | grep -F " + sq(comm) + " | grep -v grep;  -- EUID 应与配置用户一致",
		Rollback: "-- 回滚：还原单元文件改动（systemctl cat 记录的原内容），systemctl daemon-reload && systemctl restart " + unitRef + "。",
		Note:     "切到非 root 运行后最常见的问题是日志/数据目录权限不足，先看 journalctl -u <单元> 再放行目录属主，不要直接改回 root 了事。",
	}
}

func linuxHighCaps(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "linux.proc_scan")
	if f == nil {
		return nil
	}
	exe := f.Attributes["exe"]
	caps := f.Attributes["caps"]
	if exe == "" || caps == "" {
		return nil
	}
	// caps 形如 "[cap_net_bind_service cap_sys_admin]" 或逗号分隔：归一为 setcap 表达式
	names := strings.Fields(strings.Trim(caps, "[]"))
	rbExpr := strings.Join(names, ",") + "+ep"
	return &Script{
		RuleID: "os.linux.high_capabilities", Subject: subject, Scope: exe,
		Precheck: fmt.Sprintf("getcap %s; ps -eo user,euid,comm,args | grep -F %s | grep -v grep", exe, exe),
		Fix:      fmt.Sprintf("setcap -r %s", exe),
		Verify:   fmt.Sprintf("getcap %s;  -- 应无输出；重启对应服务后复采确认进程 CapEff 为 0", exe),
		Rollback: fmt.Sprintf("setcap %s %s", sq(rbExpr), exe),
		Note:     "回滚表达式按「证据中的能力名集合 +ep」重建，与原始文件能力在名称集合上等价；若原能力含 permitted/inheritable 的精细区分，请以 getcap 的原始记录为准微调。清零后若服务因缺 CAP_NET_BIND_SERVICE 等能力起不来，应改为 systemd 单元的 AmbientCapabilities 按需授予并走基线。",
	}
}

// linuxWritableFile mode 精确对：收紧 = 清除 group/other 写位；回滚 = 原 mode。
func linuxWritableFile(subject string, ev []facts.Fact) *Script {
	var f *facts.Fact
	for i := range ev {
		if ev[i].Kind == facts.FactFilePerm && ev[i].Attributes["mode"] != "" {
			f = &ev[i]
			break
		}
	}
	if f == nil {
		for i := range ev {
			if ev[i].Attributes["mode"] != "" && ev[i].Attributes["path"] != "" {
				f = &ev[i]
				break
			}
		}
	}
	if f == nil {
		return nil
	}
	path := f.Attributes["path"]
	if path == "" {
		path = f.Subject
	}
	modeStr := strings.TrimPrefix(f.Attributes["mode"], "0")
	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		return nil
	}
	tight := mode &^ 0o022
	return &Script{
		RuleID: "os.linux.writable_service_file", Subject: subject, Scope: path,
		Precheck: fmt.Sprintf("ls -l %s; stat -c '%%a %%U:%%G' %s", path, path),
		Fix:      fmt.Sprintf("chmod %04o %s", tight, path),
		Verify:   fmt.Sprintf("stat -c '%%a' %s;  -- 应为 %04o（group/other 写位已清除）", path, tight),
		Rollback: fmt.Sprintf("chmod %04o %s", mode, path),
		Note:     "只收紧权限位，不动属主；若 group 写是同组运维的既定协作方式，应改为把服务文件迁到 root 属主目录或走基线备案，而不是长期保留可写。",
	}
}

// mwPermScript 中间件配置可写（Tomcat/Nginx/WebLogic 共用，attrs 同构：
// path/mode/owner/group + writable 标记）。与 linuxWritableFile 同口径。
func mwPermScript(ruleID string) generator {
	return func(subject string, ev []facts.Fact) *Script {
		var f *facts.Fact
		for i := range ev {
			if ev[i].Attributes["mode"] != "" && ev[i].Attributes["path"] != "" {
				f = &ev[i]
				break
			}
		}
		if f == nil {
			return nil
		}
		path := f.Attributes["path"]
		modeStr := strings.TrimPrefix(f.Attributes["mode"], "0")
		mode, err := strconv.ParseUint(modeStr, 8, 32)
		if err != nil {
			return nil
		}
		tight := mode &^ 0o022
		return &Script{
			RuleID: ruleID, Subject: subject, Scope: path,
			Precheck: fmt.Sprintf("ls -ld %s", path),
			Fix:      fmt.Sprintf("chmod %04o %s", tight, path),
			Verify:   fmt.Sprintf("stat -c '%%a %%U:%%G' %s;  -- mode 应为 %04o", path, tight),
			Rollback: fmt.Sprintf("chmod %04o %s", mode, path),
			Note:     "只收紧权限位；属主保持 " + f.Attributes["owner"] + ":" + f.Attributes["group"] + " 不变。若运行账号需写该目录（如部署目录），应拆分只读配置与可写数据目录，而非放宽配置目录。",
		}
	}
}
