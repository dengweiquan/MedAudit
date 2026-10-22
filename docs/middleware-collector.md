# 中间件采集器（M7-1：Tomcat / Nginx）

## 用法

在中间件所在主机上运行（只读，不发网络请求、不改配置）：

- Tomcat：medaudit-collector mw --type tomcat --home <CATALINA_HOME> --out bundle.zip --hospital <id> --asset <id> --plan <id>
- Nginx：medaudit-collector mw --type nginx --home <配置目录或 nginx.conf> --out bundle.zip ...
- 回传：medaudit-collector bundle upload --file bundle.zip --server <平台地址>

## 采集内容

- Tomcat：实例版本（catalina.jar MANIFEST）、进程运行身份（/proc 按 catalina.home 匹配）、
  server.xml 连接器（端口/TLS/绑定地址/SSLProtocol）、tomcat-users 账号与角色（**口令与哈希不采集**，
  结构体刻意不解析 password 属性）、webapps 部署清单（manager/host-manager/examples/docs 标记）、
  conf 与 webapps 权限。
- Nginx：配置全量解析（含 include 展开）：user 指令、server/listen（含 ssl 标记与绑定地址）、
  ssl_protocols（按 http/server 作用域）、autoindex、root；master 进程运行身份；主配置与目录权限。
  版本取 nginx -v（主机无 nginx 二进制时为空，不臆测）。

## 规则（12 条，总数 33）

mw.tomcat.* / mw.nginx.*：run_as_root、config_writable、plain_listener、tls_weak 为两产品共有维度；
Tomcat 特有 manager_deployed / console_admin / sample_apps；Nginx 特有 autoindex。
无运行进程时不产生 process 事实，run_as_root 结论为 UNKNOWN（不臆测为通过）。

## 验收（2026-10-20，kf7 夹具 /opt/mw-fixtures）

- Tomcat 9.0.85 夹具植入 6 类问题（manager 部署、manager-gui 账号、示例应用、明文 8080、
  弱 TLS 8443、conf 0777）：目录采集评估 8 FAIL 全命中且零误报（manager-status 账号未误报）；
  容器运行后 run_as_root 追加命中（9 FAIL）；收紧（删账号/应用、绑回环、TLS1.2+、chmod 750）后 0 FAIL。
  事实包全文校验不含植入口令字符串。
- Nginx 夹具植入 5 项（明文 8081、http 与 server 两级弱 TLS、autoindex、nginx.conf 0777）：
  5 FAIL 全命中（回环 8082 正确未报）；容器运行后 run_as_root 命中；收紧后 0 FAIL。
- 夹具目录保留在 /opt/mw-fixtures（当前为收紧态，植入方法见本文件与 git 历史）。

## 边界

仅 Linux 主机；WebLogic / IIS 在 M7-2（未立项前 Web 仅登记）；不做口令测试、CVE 扫描与远程探测。
## M7-2 追加（WebLogic / IIS）

### WebLogic

- 用法：medaudit-collector mw --type weblogic --home <域根目录>（或直接指向 config/config.xml）
- 采集：域实例（域名/生产模式/管理服务器）、各服务器监听（端口/地址/SSL 启用与端口/角色）、
  app-deployment 清单（console 标记）、域目录与 config 权限、weblogic.Server 进程运行身份。
- **不采集**：嵌入式 LDAP 内的用户/组（二进制 .dat 存储）——事实缺口，规则不对其下结论。
- 规则 5 条：mw.weblogic.{run_as_root, config_writable, dev_mode, console_deployed, plain_listener}。
- 验证为**目录级**（2026-10-20，/opt/mw-fixtures/wls-domain 构造域，真实 config.xml 格式）：
  植入 5 FAIL 全命中（开发模式/控制台部署/双明文监听/配置 0777）；收紧（生产模式/删控制台/
  绑回环/chmod 640）后 0 FAIL。无在线域实测（镜像授权限制，与计划一致）。

### IIS

- 用法：medaudit-collector.exe mw --type iis [--home <applicationHost.config 路径或目录>]；
  --home 为空时取 %SystemRoot%\System32\inetsrv\config\applicationHost.config。
- 采集：站点与绑定（协议/IP/端口/主机头）、站点认证（location 覆盖或架构默认值，事实注明来源）、
  授权规则开放度、应用程序池进程模型身份（LocalSystem 等）。
- **不采集**：配置文件 Windows ACL（由 OS 采集的主机文件 ACL 事实覆盖面之外，本采集器不下此结论）。
- 规则 4 条：mw.iis.{plain_binding, anon_open, apppool_system, default_site}。
- 验证两级：① 配置夹具（/opt/mw-fixtures/iis）植入 6 FAIL 全命中零误报，收紧版 0 FAIL；
  ② win2019-test 实机：装 Web-Server 角色后植入 HIS 站点（8081 + HisPool=LocalSystem），
  在虚机内运行 Windows 版采集器走默认路径采集并直传平台，评估 6 FAIL 与植入完全一致（默认站点 3 项 + HIS 明文/匿名 + HisPool LocalSystem）。

规则总数：33（M7-1）+ 9（M7-2）= 42。

## M8-1 增补（2026-10-21）：跨层关联的中间件侧
关联引擎会消费中间件事实包的文件权限（含组名，本轮 permAttrs 补 gid/group）、
控制台账号角色与进程运行身份，构建「可写配置 → 控制实例 → 以运行身份执行」链路。
