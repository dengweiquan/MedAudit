package remediation

import (
	"fmt"
	"strings"

	"medaudit/internal/facts"
)

func init() {
	generators["mw.weblogic.run_as_root"] = weblogicRunRoot
	generators["mw.weblogic.dev_mode"] = weblogicDevMode
	generators["mw.weblogic.console_deployed"] = weblogicConsole
	generators["mw.weblogic.plain_listener"] = weblogicPlainListener
}

func weblogicRunRoot(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "mw.weblogic.process")
	if f == nil {
		return nil
	}
	return &Script{
		RuleID: "mw.weblogic.run_as_root", Subject: subject,
		Precheck: "ps -o user,pid,args -p " + f.Attributes["pid"] + "; ls -ld $DOMAIN_HOME",
		Fix: "-- 指导型整改：WebLogic 当前以 root 运行，改为域属主账号（以 oracle 为例）：\n" +
			"-- 1) chown -R oracle:oracle $DOMAIN_HOME（及域外置的日志/密钥目录）；\n" +
			"-- 2) systemd 单元加 User=oracle，或启动脚本以 su oracle -c 方式拉起；Node Manager 启动方式同步调整；\n" +
			"-- 3) 重启后复核进程用户与日志写入。",
		Verify:   "ps aux | grep -F weblogic.Server | grep -v grep;  -- 进程用户应为非 root",
		Rollback: "-- 回滚：去掉单元 User=（或恢复原启动方式）并重启；属主改动无需回滚。",
		Note:     "域目录中的 boot.properties 与 SerializedSystemIni.dat 属主不对会导致启动失败，切换前先用目标账号做一次只读遍历检查（find $DOMAIN_HOME ! -user oracle）。",
	}
}

func weblogicDevMode(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "mw.weblogic.instance")
	if f == nil {
		return nil
	}
	domain := f.Attributes["domain"]
	return &Script{
		RuleID: "mw.weblogic.dev_mode", Subject: subject,
		Precheck: "grep -n 'production-mode-enabled' $DOMAIN_HOME/config/config.xml",
		Fix: "-- 指导型整改（WLST，域 " + domain + "）：\n" +
			"-- connect('<管理用户>','<口令>','t3://<管理地址>:<端口>')\n" +
			"-- edit(); startEdit(); cmo.setProductionModeEnabled(true); save(); activate()\n" +
			"-- 或控制台：域 > 配置 > 常规，勾选「生产模式」后激活更改。改后需重启管理服务器生效。",
		Verify:   "grep -n 'production-mode-enabled' $DOMAIN_HOME/config/config.xml;  -- 应为 true；重启后控制台横幅不再显示开发模式",
		Rollback: "-- 回滚：同样路径把 ProductionModeEnabled 设回 false 并重启管理服务器。",
		Note:     "切生产模式后，开发模式的自动部署、未锁定编辑等便利会被收紧；先在维护窗口把待部署应用改走正式部署流程再切换。",
	}
}

func weblogicConsole(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "mw.weblogic.deployments")
	if f == nil {
		return nil
	}
	target := f.Attributes["target"]
	return &Script{
		RuleID: "mw.weblogic.console_deployed", Subject: subject,
		Precheck: "-- WLST: connect 后 print getMBean('/AppDeployments') 或控制台「部署」页确认 console 部署目标（当前目标：" + target + "）",
		Fix: "-- 指导型整改：管理控制台只应保留在管理服务器、且只经管理通道访问：\n" +
			"-- (a) 若 console 被部署到非管理目标（" + target + "）：在控制台「部署」中把 console 的目标收回到管理服务器；\n" +
			"-- (b) 更严格：启用管理端口（Administration Port）并关闭管理服务器的普通监听给控制台用，或在 config.xml 关闭 console（<console-enabled>false</console-enabled>，域级 ConsoleMBean）。\n" +
			"-- 变更经 WLST/控制台激活后按提示重启相关服务器。",
		Verify:   "-- 以普通业务通道地址访问 /console 应不可达；管理通道仍可登录控制台",
		Rollback: "-- 回滚：把 console 目标/ConsoleMBean 设置按 Precheck 记录的原值恢复并激活。",
		Note:     "console 是产品组件、随域配置管理，不要按普通应用 undeploy 删除其部署记录——处置点是「目标范围与访问通道」，不是删除应用文件。",
	}
}

func weblogicPlainListener(subject string, ev []facts.Fact) *Script {
	var f *facts.Fact
	for i := range ev {
		if ev[i].Source == "mw.weblogic.servers" {
			f = &ev[i]
			break
		}
	}
	if f == nil {
		return nil
	}
	srv := strings.TrimPrefix(f.Subject, "server:")
	port := f.Attributes["listen_port"]
	return &Script{
		RuleID: "mw.weblogic.plain_listener", Subject: subject,
		Precheck: fmt.Sprintf("ss -ltnp | grep ':%s '; grep -n -A6 '<name>%s</name>' $DOMAIN_HOME/config/config.xml | head -12", port, srv),
		Fix: "-- 指导型整改（WLST，服务器 " + srv + "，当前明文端口 " + port + "）：\n" +
			"-- connect 后：edit(); startEdit()\n" +
			"-- cd('/Servers/" + srv + "'); cmo.setListenPortEnabled(false)\n" +
			"-- cd('/Servers/" + srv + "/SSL/" + srv + "'); cmo.setEnabled(true)（并确认 SSL 监听端口与演示/正式证书就绪）\n" +
			"-- save(); activate()，重启该服务器生效。",
		Verify:   fmt.Sprintf("ss -ltnp | grep ':%s ';  -- 明文端口应消失；https 端口可连", port),
		Rollback: "-- 回滚：WLST 把 ListenPortEnabled 设回 true（SSL 设置保持无碍），激活后重启该服务器。",
		Note:     "关明文前先把负载均衡/探活/应用回调的地址改到 https 或管理通道；仅绑管理地址的场景也可改为设置 ListenAddress 为内网管理 IP 保留明文（配合基线）。",
	}
}

var _ = strings.TrimSpace
