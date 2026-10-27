package remediation

import (
	"fmt"
	"strings"

	"medaudit/internal/facts"
)

func init() {
	generators["os.windows.unexpected_admin"] = winUnexpectedAdmin
	generators["os.windows.svc_account_mismatch"] = winSvcMismatch
	generators["os.windows.writable_service_binary"] = winWritableBinary
	generators["mw.iis.plain_binding"] = iisPlainBinding
	generators["mw.iis.anon_open"] = iisAnonOpen
	generators["mw.iis.apppool_system"] = iisAppPoolSystem
	generators["mw.iis.default_site"] = iisDefaultSite
}

func winUnexpectedAdmin(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "win.group_enum")
	if f == nil {
		return nil
	}
	group := f.Attributes["group"]
	if group == "" {
		group = "Administrators"
	}
	adName := subject
	if i := strings.LastIndex(subject, `\`); i >= 0 {
		adName = subject[i+1:]
	}
	// 域控没有本地 SAM 组（LocalGroupMember 报 Group not found），必须走
	// AD 组命令；脚本按 DomainRole 自适应（M15 二期 win2019 域控实证）。
	branch := func(localCmd, adCmd string) string {
		return fmt.Sprintf("if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { %s } else { %s }", adCmd, localCmd)
	}
	note := "移除后该账号立即失去管理员权（已登录会话需重新登录生效）。确为运维必需的应走基线备案。域控上本地组命令不可用，脚本按机器角色（DomainRole ≥ 4 为域控）自动分支走 AD 组命令。"
	if strings.HasSuffix(strings.ToUpper(subject), `\ADMINISTRATOR`) {
		note = "这是内置 Administrator 账号：其 Administrators 成员资格是系统默认形态，常规处置是禁用账号或走基线备案，而非移除成员资格——下列命令仅在明确评审后执行。"
	}
	return &Script{
		RuleID: "os.windows.unexpected_admin", Subject: subject,
		Precheck: branch(
			fmt.Sprintf("Get-LocalGroupMember -Group %s | Format-Table Name, ObjectClass", sq(group)),
			fmt.Sprintf("Get-ADGroupMember -Identity %s | Format-Table SamAccountName", sq(group))),
		Fix: branch(
			fmt.Sprintf("Remove-LocalGroupMember -Group %s -Member %s -Confirm:$false", sq(group), sq(subject)),
			fmt.Sprintf("Remove-ADGroupMember -Identity %s -Members %s -Confirm:$false", sq(group), sq(adName))),
		Verify: fmt.Sprintf("复采评估确认，或在目标机复查管理员组（域控 Get-ADGroupMember、成员机 Get-LocalGroupMember）：结果中不应再有 %s", subject),
		Rollback: branch(
			fmt.Sprintf("Add-LocalGroupMember -Group %s -Member %s", sq(group), sq(subject)),
			fmt.Sprintf("Add-ADGroupMember -Identity %s -Members %s", sq(group), sq(adName))),
		Note: note,
	}
}

func winSvcMismatch(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "win.proc_token")
	if f == nil {
		return nil
	}
	cfg := f.Attributes["configured_user"]
	act := f.Attributes["actual_user"]
	if cfg == "" || act == "" {
		return nil
	}
	return &Script{
		RuleID: "os.windows.svc_account_mismatch", Subject: subject,
		Precheck: fmt.Sprintf("sc.exe qc %s; sc.exe queryex %s; Get-CimInstance Win32_Service -Filter \"Name='%s'\" | Select-Object Name, StartName, State", subject, subject, subject),
		Fix: "-- 指导型整改：配置身份 " + cfg + " 与实际运行身份 " + act + " 不一致，二选一：\n" +
			"-- (a) 配置为准（推荐）：重启服务使配置生效 —— Restart-Service " + subject + "；若仍不一致，查启动脚本/组策略是否改写了 StartName。\n" +
			"-- (b) 实际为准：把配置改成实际身份 —— sc.exe config " + subject + " obj= \"" + act + "\"（域账号还需 password= 参数），再 Restart-Service " + subject + "。",
		Verify:   "Get-CimInstance Win32_Service -Filter \"Name='" + subject + "'\" | Select-Object StartName;  -- 并复采确认进程令牌身份与配置一致",
		Rollback: "-- 回滚：sc.exe config " + subject + " obj= \"<原配置身份>\" 后 Restart-Service；(a) 路径无需回滚动作，复采确认即可。",
		Note:     "服务名以服务控制管理器中的为准（Precheck 输出核对）；含空格的服务名在 sc.exe 中须加引号。改身份后首次启动失败多为新身份缺日志/数据目录权限。",
	}
}

func winWritableBinary(subject string, ev []facts.Fact) *Script {
	f := firstFact(ev, "win.acl_check")
	if f == nil {
		return nil
	}
	path := f.Subject
	hits := f.Attributes["ace_hits"]
	save := `C:\medaudit-acl-backup.txt`
	return &Script{
		RuleID: "os.windows.writable_service_binary", Subject: subject, Scope: path,
		Precheck: fmt.Sprintf("icacls %s\nicacls %s /save %s", sq(path), sq(path), save),
		Fix: "-- 指导型整改：命中 ACE：" + hits + "\n" +
			"-- 先执行 Precheck 把当前 ACL 存入 " + save + "（回滚依赖它，不要跳过）；\n" +
			"-- 然后按命中主体逐条回收写权限，例如：icacls " + sq(path) + " /remove:g \"<低权主体>\"\n" +
			"-- 或收紧为只读：icacls " + sq(path) + " /grant \"<低权主体>:(RX)\"（先 remove 旧授权再 grant）。",
		Verify:   fmt.Sprintf("icacls %s;  -- 低权主体不应再有 W/F 授权", sq(path)),
		Rollback: fmt.Sprintf("icacls %s /restore %s", sq(path), save),
		Note:     "ACL 的精确回滚依赖 Precheck 的 /save 快照文件——这是本脚本唯一不能省略的前置步骤。服务若是路径穿越类风险（目录也可写），对父目录同样处理。",
	}
}

// ---------- IIS（appcmd 精确对） ----------

const appcmd = `%windir%\system32\inetsrv\appcmd`

func iisPlainBinding(subject string, ev []facts.Fact) *Script {
	var bf *facts.Fact
	for i := range ev {
		if strings.HasPrefix(ev[i].Subject, "binding:") || ev[i].Source == "mw.iis.sites" {
			bf = &ev[i]
			break
		}
	}
	if bf == nil {
		return nil
	}
	site := bf.Attributes["site"]
	ip := bf.Attributes["ip"]
	port := bf.Attributes["port"]
	host := bf.Attributes["host"]
	if site == "" || port == "" {
		return nil
	}
	if ip == "" {
		ip = "*"
	}
	bindInfo := ip + ":" + port + ":" + host
	return &Script{
		RuleID: "mw.iis.plain_binding", Subject: subject,
		Precheck: fmt.Sprintf("%s list site %s /text:bindings", appcmd, sq(site)),
		Fix: "-- 前置条件：站点证书已装入 LocalMachine\\My 且完成 443 绑定（netsh http add sslcert ipport=<IP>:443 certhash=<指纹> appid={任意GUID}）。\n" +
			fmt.Sprintf("%s set site %s /+bindings.[protocol='https',bindingInformation='*:443:%s']\n", appcmd, sq(site), host) +
			fmt.Sprintf("%s set site %s /-bindings.[protocol='http',bindingInformation='%s']", appcmd, sq(site), bindInfo),
		Verify:   fmt.Sprintf("%s list site %s /text:bindings;  -- 应只剩 https 绑定", appcmd, sq(site)),
		Rollback: fmt.Sprintf("%s set site %s /+bindings.[protocol='http',bindingInformation='%s']", appcmd, sq(site), bindInfo),
		Note:     "删除 http 绑定后存量明文客户端立即不可达；过渡期可先保留 http 并做 301 跳转 https（URL Rewrite），稳定后再执行本脚本的删除步。回滚只恢复 http 绑定，https 绑定保留无碍。",
	}
}

func iisAnonOpen(subject string, ev []facts.Fact) *Script {
	var af *facts.Fact
	for i := range ev {
		if ev[i].Source == "mw.iis.auth" {
			af = &ev[i]
			break
		}
	}
	if af == nil {
		return nil
	}
	site := af.Attributes["site"]
	if site == "" {
		site = subject
	}
	return &Script{
		RuleID: "mw.iis.anon_open", Subject: subject, Scope: site,
		Precheck: fmt.Sprintf("%s list config %s /section:system.webServer/security/authentication/anonymousAuthentication", appcmd, sq(site)),
		Fix:      fmt.Sprintf("%s set config %s /section:system.webServer/security/authentication/anonymousAuthentication /enabled:false /commit:apphost", appcmd, sq(site)),
		Verify:   fmt.Sprintf("%s list config %s /section:system.webServer/security/authentication/anonymousAuthentication;  -- enabled 应为 False，并以未登录浏览器验证返回 401", appcmd, sq(site)),
		Rollback: fmt.Sprintf("%s set config %s /section:system.webServer/security/authentication/anonymousAuthentication /enabled:true /commit:apphost", appcmd, sq(site)),
		Note:     "关闭匿名后该站点全部内容需登录；若站点含必须公开的区域，应改为按目录（location）分别设置，而不是整站二选一。本项与授权规则（authorization）联动：只关匿名但授权仍开放的风险在复测中会以其它项呈现。",
	}
}

func iisAppPoolSystem(subject string, ev []facts.Fact) *Script {
	var pf *facts.Fact
	for i := range ev {
		if ev[i].Source == "mw.iis.pools" {
			pf = &ev[i]
			break
		}
	}
	if pf == nil {
		return nil
	}
	pool := strings.TrimPrefix(pf.Subject, "apppool:")
	if pf.Attributes["name"] != "" {
		pool = pf.Attributes["name"]
	}
	cur := pf.Attributes["identity_type"]
	if cur == "" {
		cur = "LocalSystem"
	}
	return &Script{
		RuleID: "mw.iis.apppool_system", Subject: subject, Scope: pool,
		Precheck: fmt.Sprintf("%s list apppool %s /text:processModel.identityType", appcmd, sq(pool)),
		Fix:      fmt.Sprintf("%s set apppool %s /processModel.identityType:ApplicationPoolIdentity\n%s recycle apppool %s", appcmd, sq(pool), appcmd, sq(pool)),
		Verify:   fmt.Sprintf("%s list apppool %s /text:processModel.identityType;  -- 应为 ApplicationPoolIdentity；访问站点确认无 500/503", appcmd, sq(pool)),
		Rollback: fmt.Sprintf("%s set apppool %s /processModel.identityType:%s\n%s recycle apppool %s", appcmd, sq(pool), cur, appcmd, sq(pool)),
		Note:     "改身份后应用对站点目录的访问身份变为 IIS AppPool\\<池名> 虚拟账号：站点目录与上传目录需给该虚拟账号授权；连数据库用 Windows 集成登录的，要同步在库侧建对应登录。回收（recycle）会短暂中断在途请求，放在维护窗口。",
	}
}

func iisDefaultSite(subject string, ev []facts.Fact) *Script {
	return &Script{
		RuleID: "mw.iis.default_site", Subject: subject,
		Precheck: fmt.Sprintf("%s list site \"Default Web Site\"\n%s add backup \"M15-DefaultSite\"", appcmd, appcmd),
		Fix:      fmt.Sprintf("%s delete site \"Default Web Site\"", appcmd),
		Verify:   fmt.Sprintf("%s list site \"Default Web Site\";  -- 应提示找不到该站点；curl 本机 80 端口应无默认页响应", appcmd),
		Rollback: fmt.Sprintf("%s restore backup \"M15-DefaultSite\"", appcmd),
		Note:     "本项按「站点存在」判定（采集器读 applicationHost.config，不看运行状态），仅停止站点不会消除本项，必须删除。回滚依赖 Precheck 的 appcmd 配置备份（add backup）——restore 会把整个 applicationHost.config 还原到备份时点，备份与删除之间不要再做其它 IIS 配置变更。长期不用默认站时删除即终态，无需回滚。",
	}
}
