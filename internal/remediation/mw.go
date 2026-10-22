package remediation

import (
	"fmt"
	"strings"

	"medaudit/internal/facts"
)

// 配置文件备份先行模式（与 sudoers 同理）：改前整文件 cp 备份，回滚整份还原。
func backupPair(file string) (bak, restore string) {
	bak = file + ".m15-rollback"
	return bak, fmt.Sprintf("cp -a %s %s", bak, file)
}

func init() {
	generators["mw.tomcat.config_writable"] = mwPermScript("mw.tomcat.config_writable")
	generators["mw.nginx.config_writable"] = mwPermScript("mw.nginx.config_writable")
	generators["mw.weblogic.config_writable"] = mwPermScript("mw.weblogic.config_writable")
	generators["mw.tomcat.run_as_root"] = tomcatRunRoot
	generators["mw.nginx.run_as_root"] = nginxRunRoot
	generators["mw.tomcat.manager_deployed"] = tomcatDeployRename("mw.tomcat.manager_deployed")
	generators["mw.tomcat.sample_apps"] = tomcatDeployRename("mw.tomcat.sample_apps")
	generators["mw.tomcat.console_admin"] = tomcatConsoleAdmin
	generators["mw.tomcat.plain_listener"] = tomcatPlainListener
	generators["mw.tomcat.tls_weak"] = tomcatTLSWeak
	generators["mw.nginx.plain_listener"] = nginxPlainListener
	generators["mw.nginx.tls_weak"] = nginxTLSWeak
	generators["mw.nginx.autoindex"] = nginxAutoindex
}

func mwHome(ev []facts.Fact, fallback string) string {
	if f := firstFact(ev, "mw.tomcat.instance"); f != nil && f.Attributes["home"] != "" {
		return f.Attributes["home"]
	}
	return fallback
}

func tomcatRunRoot(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "mw.tomcat.process")
	if f == nil {
		return nil
	}
	home := mwHome(ev, "$CATALINA_HOME")
	return &Script{
		RuleID: "mw.tomcat.run_as_root", Subject: subject,
		Precheck: fmt.Sprintf("ps -o user,pid,args -p %s; ls -ld %s %s/conf %s/webapps", f.Attributes["pid"], home, home, home),
		Fix: "-- 指导型整改：Tomcat 当前以 root 运行，改为专用账号（以 tomcat 为例）：\n" +
			"-- 1) id tomcat 不存在则 useradd -r -s /sbin/nologin tomcat；\n" +
			"-- 2) chown -R tomcat:tomcat " + home + "（logs/temp/work/webapps 必须可写，conf 只读即可）；\n" +
			"-- 3) systemd 单元加 User=tomcat（或用 setenv/启动脚本 su tomcat -c 方式启动）；\n" +
			"-- 4) 重启服务后以 Precheck 复核 run_user。",
		Verify:   "ps aux | grep -F catalina | grep -v grep;  -- 进程用户应为 tomcat 等非 root 账号；访问应用确认日志正常写入",
		Rollback: "-- 回滚：单元去掉 User=（或恢复原启动方式）并重启；属主改动无需回滚（不影响 root 运行）。",
		Note:     "若 Connector 使用 80/443 特权端口，非 root 进程绑定需 authbind 或 CAP_NET_BIND_SERVICE（或由前置 Nginx/负载转发），先确认监听方案再切换账号。",
	}
}

func nginxRunRoot(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "mw.nginx.process")
	if f == nil {
		return nil
	}
	conf := ""
	if inst := firstFact(ev, "mw.nginx.instance"); inst != nil {
		conf = inst.Attributes["config"]
	}
	cfgUser := f.Attributes["configured_user"]
	if cfgUser == "" {
		cfgUser = "nginx/www-data"
	}
	return &Script{
		RuleID: "mw.nginx.run_as_root", Subject: subject,
		Precheck: "ps -eo user,comm,args | grep -F nginx | grep -v grep; grep -n '^user' " + orStr(conf, "/etc/nginx/nginx.conf"),
		Fix: "-- 指导型整改：master 以 root 启动本身是 Nginx 的常规形态（绑特权端口后派生 worker）；\n" +
			"-- 本项命中说明 worker 也在以 root 运行或 user 指令配置为 root。把主配置 user 指令改为非 root 账号：\n" +
			"--   user " + cfgUser + ";（当前为 root 时改成本行；无 user 指令时在 main 段首行添加）\n" +
			"-- 并确认 client_body/proxy/fastcgi 临时目录与日志目录对该账号可写，然后 nginx -t && nginx -s reload（或重启服务）。",
		Verify:   "ps -eo user,comm | grep -F nginx;  -- worker 进程用户应为非 root",
		Rollback: "-- 回滚：user 指令改回 root（或删除该行）后 nginx -t && nginx -s reload。",
		Note:     "主配置路径以 Precheck 的 grep 结果为准（证据配置：" + orStr(conf, "未采集到") + "）。",
	}
}

func orStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// tomcatDeployRename 改名停用：manager/示例应用从 webapps 移出即停用，mv 可逆。
func tomcatDeployRename(ruleID string) generator {
	return func(subject string, ev []facts.Fact) *Script {
		f := firstFact(ev, "mw.tomcat.deployments")
		if f == nil {
			return nil
		}
		path := f.Attributes["path"]
		if path == "" {
			return nil
		}
		disabled := path + ".disabled-m15"
		return &Script{
			RuleID: ruleID, Subject: subject, Scope: path,
			Precheck: fmt.Sprintf("ls -ld %s", path),
			Fix:      fmt.Sprintf("mv %s %s", path, disabled),
			Verify:   fmt.Sprintf("ls %s;  -- webapps 下不应再有该应用目录；重启/热部署后访问 /%s 应为 404", dirOf(path), subject),
			Rollback: fmt.Sprintf("mv %s %s", disabled, path),
			Note:     "改名停用不删除文件，回滚即恢复；若该应用被显式部署描述符（conf/Catalina）引用，需同步处理该描述符。若业务确需 manager，应改用 manager-status 最小角色 + 来源 IP 限制（RemoteAddrValve）并走基线。",
		}
	}
}

func dirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i > 0 {
		return p[:i]
	}
	return p
}

func tomcatConsoleAdmin(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "mw.tomcat.users")
	if f == nil {
		return nil
	}
	roles := f.Attributes["roles"]
	home := mwHome(ev, "$CATALINA_HOME")
	file := home + "/conf/tomcat-users.xml"
	bak, restore := backupPair(file)
	return &Script{
		RuleID: "mw.tomcat.console_admin", Subject: subject,
		Precheck: fmt.Sprintf("grep -n 'username=%q' %s", subject, file),
		Fix: strings.Join([]string{
			fmt.Sprintf("cp -a %s %s", file, bak),
			fmt.Sprintf("sed -i '/username=\"%s\"/s/roles=\"[^\"]*\"/roles=\"\"/' %s", subject, file),
			fmt.Sprintf("grep -n 'username=\"%s\"' %s", subject, file),
		}, "\n"),
		Verify:   fmt.Sprintf("grep -n 'username=\"%s\"' %s;  -- roles 应为空；重启 Tomcat 后该用户访问 /manager 应被拒绝", subject, file),
		Rollback: restore,
		Note:     fmt.Sprintf("原角色为 %s（回滚文件即原样恢复）。只剥离管理角色、账号本身保留；若该账号已无人使用，更彻底的做法是整行删除该 <user>。改后须重启 Tomcat 才生效。", roles),
	}
}

func tomcatPlainListener(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "mw.tomcat.server_xml")
	if f == nil {
		return nil
	}
	port := f.Attributes["port"]
	home := mwHome(ev, "$CATALINA_HOME")
	file := home + "/conf/server.xml"
	bak, restore := backupPair(file)
	return &Script{
		RuleID: "mw.tomcat.plain_listener", Subject: subject,
		Precheck: fmt.Sprintf("grep -n 'port=\"%s\"' %s; ss -ltnp | grep ':%s '", port, file, port),
		Fix: "-- 指导型整改（先备份 " + bak + "）：在 server.xml 中定位 port=\"" + port + "\" 的 Connector，二选一：\n" +
			"-- (a) 仅本机/内网管理用途：给该 Connector 加 address=\"127.0.0.1\" 限定回环；\n" +
			"-- (b) 对外服务：删除或注释该明文 Connector，只保留 SSL Connector，并把 redirectPort 指向 SSL 端口。\n" +
			"cp -a " + file + " " + bak + "\n-- 编辑后重启 Tomcat 生效。",
		Verify:   fmt.Sprintf("ss -ltnp | grep ':%s '; curl -s -o /dev/null -w '%%{http_code}' http://127.0.0.1:%s/ ;  -- 明文应不可达或仅回环", port, port),
		Rollback: restore + "\n# 还原后重启 Tomcat",
		Note:     "动 Connector 前先确认该端口的调用方（应用/探活/负载均衡）走的是哪个协议，避免把业务端口当管理端口关掉。",
	}
}

func tomcatTLSWeak(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "mw.tomcat.server_xml")
	if f == nil {
		return nil
	}
	proto := f.Attributes["ssl_protocol"]
	home := mwHome(ev, "$CATALINA_HOME")
	file := home + "/conf/server.xml"
	bak, restore := backupPair(file)
	return &Script{
		RuleID: "mw.tomcat.tls_weak", Subject: subject,
		Precheck: fmt.Sprintf("grep -n 'sslProtocol\\|protocols=' %s; echo | openssl s_client -connect 127.0.0.1:%s -tls1_1 2>/dev/null | grep -c 'Verify return code'", file, portOf(subject)),
		Fix: "-- 指导型整改（先备份 " + bak + "）：当前协议集 " + proto + "。\n" +
			"-- 新式写法（SSLHostConfig）：protocols=\"TLSv1.2,TLSv1.3\"；老式写法（Connector）：sslProtocol=\"TLSv1.2\" 并配合 sslEnabledProtocols=\"TLSv1.2,TLSv1.3\"。\n" +
			"cp -a " + file + " " + bak + "\n-- 编辑后重启 Tomcat 生效。",
		Verify:   "echo | openssl s_client -connect 127.0.0.1:" + portOf(subject) + " -tls1_1 2>/dev/null | grep 'alert\\|Verify return code: 0 ';  -- TLS1.1 应握手失败、TLS1.2 应成功",
		Rollback: restore + "\n# 还原后重启 Tomcat",
		Note:     "收紧后老旧客户端（Java 6/老浏览器）将无法连接；先在 Precheck 里核对该端口的调用方清单。",
	}
}

func portOf(subject string) string {
	if i := strings.LastIndex(subject, ":"); i >= 0 {
		return subject[i+1:]
	}
	return subject
}

func nginxPlainListener(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "mw.nginx.listeners")
	if f == nil {
		return nil
	}
	port := f.Attributes["port"]
	name := f.Attributes["server_name"]
	return &Script{
		RuleID: "mw.nginx.plain_listener", Subject: subject,
		Precheck: fmt.Sprintf("nginx -T 2>/dev/null | grep -n 'listen %s\\|server_name %s' ; ss -ltnp | grep ':%s '", port, name, port),
		Fix: "-- 指导型整改：在 nginx -T 输出中定位 listen " + port + "（server_name " + name + "）的 server 块，二选一：\n" +
			"-- (a) 已有证书：新增 listen 443 ssl 并补 ssl_certificate/ssl_certificate_key，原 " + port + " 块改为 301 跳转 https；\n" +
			"-- (b) 仅内部使用：listen 改为 127.0.0.1:" + port + " 限定回环。\n" +
			"-- 改前 cp 备份对应配置文件，改后 nginx -t && nginx -s reload。",
		Verify:   fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' http://127.0.0.1:%s/;  -- 明文应跳转/拒绝/仅回环", port),
		Rollback: "-- 回滚：还原备份的配置文件后 nginx -t && nginx -s reload。",
		Note:     "server_name 为 " + name + " 的块可能经 include 拆分在子文件里，以 nginx -T 的合并输出定位最终生效文件。",
	}
}

// nginxConfDir 本实例配置目录（instance 事实 config=主配置路径）；缺失回落 /etc/nginx。
func nginxConfDir(ev []facts.Fact) string {
	if inst := firstFact(ev, "mw.nginx.instance"); inst != nil && inst.Attributes["config"] != "" {
		return dirOf(inst.Attributes["config"])
	}
	return "/etc/nginx"
}

func nginxTLSWeak(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "mw.nginx.tls")
	if f == nil {
		return nil
	}
	protos := f.Attributes["protocols"]
	ctx := f.Attributes["context"]
	dir := nginxConfDir(ev)
	return &Script{
		RuleID: "mw.nginx.tls_weak", Subject: subject,
		Precheck: fmt.Sprintf("grep -rn 'ssl_protocols' %s/ 2>/dev/null; nginx -T 2>/dev/null | grep -n 'ssl_protocols'", dir),
		Fix: strings.Join([]string{
			fmt.Sprintf("F=$(grep -rl 'ssl_protocols' %s/ | head -1); cp -a $F $F.m15-rollback", dir),
			"sed -i 's|ssl_protocols[^;]*;|ssl_protocols TLSv1.2 TLSv1.3;|' $F",
			"nginx -t && nginx -s reload",
		}, "\n"),
		Verify:   "echo | openssl s_client -connect 127.0.0.1:443 -tls1_1 2>/dev/null | grep -c 'handshake failure';  -- 应 ≥1（TLS1.1 被拒）；-tls1_2 应可连",
		Rollback: fmt.Sprintf("F=$(grep -rl 'ssl_protocols' %s/ | head -1); cp -a $F.m15-rollback $F; nginx -t && nginx -s reload", dir),
		Note:     fmt.Sprintf("当前配置 %q（作用域 %s）。若 ssl_protocols 出现在多个文件/层级（http 与 server 都有），以 server 块为准逐处处理；$F 只取第一处，其余参照同一 sed 处理。", protos, ctx),
	}
}

func nginxAutoindex(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "mw.nginx.autoindex")
	if f == nil {
		return nil
	}
	ctx := f.Attributes["context"]
	dir := nginxConfDir(ev)
	return &Script{
		RuleID: "mw.nginx.autoindex", Subject: subject,
		Precheck: fmt.Sprintf("grep -rn 'autoindex on' %s/ 2>/dev/null", dir),
		Fix: strings.Join([]string{
			fmt.Sprintf("F=$(grep -rl 'autoindex on' %s/ | head -1); cp -a $F $F.m15-rollback", dir),
			"sed -i 's/autoindex[[:space:]]\\+on;/autoindex off;/' $F",
			"nginx -t && nginx -s reload",
		}, "\n"),
		Verify:   "curl -s http://127.0.0.1/ | grep -ci 'Index of';  -- 应为 0（不再列目录）",
		Rollback: fmt.Sprintf("F=$(grep -rl 'autoindex off' %s/ | head -1); cp -a $F.m15-rollback $F; nginx -t && nginx -s reload", dir),
		Note:     fmt.Sprintf("作用域：%s。若有多个文件含 autoindex on，逐个处理（$F 只取第一处）。确有文件分发需求应改用受控的索引应用并加认证，而不是裸 autoindex。", ctx),
	}
}
