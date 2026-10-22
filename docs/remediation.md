# 修复与回滚脚本（M15）

## 口径

- 报告在**生成时点**为每条 FAIL finding 生成一份脚本，存入报告快照
  （`remediation` 章节，与提权路径/漂移章节同为不可变快照；旧报告不回填）。
- 平台**只生成、人工执行**：不自动连接目标改权限。脚本须经 DBA 评审后在
  维护窗口执行；执行后用一键审计/复测确认（问题清单对应项应消失）。
- 每份脚本四件套：**前置检查**（只读，确认现状与报告一致）→ **修复命令** →
  **验证**（修复后复查）→ **回滚命令**。回滚是生成时按证据事实捕获的
  **精确逆操作**：授权的 WITH GRANT OPTION / WITH ADMIN OPTION 标志、
  sp_configure 与 ALTER SYSTEM 的原值、profile 的原 LIMIT 都取自采集事实，
  不是事后猜测。
- 没有安全模板的 FAIL（OS/中间件/业务接口与程序性事项）不生成脚本，
  报告中以「已生成 X / FAIL 共 Y」明示差额，属程序性整改。

## 一期覆盖（24 条数据库规则）

- MySQL：global_admin、grant_option、remote_no_tls、local_infile、general_log_on
- PostgreSQL：superuser、dangerous_role_attrs、public_db_create、public_writable
  （模式级与对象级）、password_encryption_weak、listen_all、
  hba_trust / hba_weak_method / hba_open_network（指导型：确切行号与内容、
  替换动作、pg_reload_conf 与回滚行）
- SQL Server：sysadmin（直接成员一条命令；经组间接为指导型，列出链路与
  两种切断方式）、control_server（直接 REVOKE；经角色中转则回收该角色的
  成员资格——影响面最小的精确切断）、xp_cmdshell、clr_enabled、
  cross_db_chaining、adhoc_distributed（sp_configure，回滚用捕获原值）
- Oracle：dba_role、sysdba_pwfile、any_privilege、cdb_dba_in_pdb、
  public_object_grant、sys_schema_grant、grant_option_spread
  （两步：回收后无转授重授；回滚为带 GRANT OPTION 的单句）、
  default_account_open（锁定/解锁，口令不变）、profile_password_policy
  （建议值可按院内制度调整，回滚恢复 UNLIMITED 原值）

快照内脚本上限 500 条（计数口径 generated 不受截断影响）；Word 章节展示
前 100 条；CSV 导出含 fix_command / rollback_command 两列（按 finding 关联）；
Web 报告详情可逐条展开并一键复制修复/回滚命令。

## 验证方式（已实证）

对四引擎在测试环境执行完整闭环：植入问题 → 采集评估 → 报告取脚本 →
执行修复 → 复采复测该项归零 → 执行回滚 → 复采复测问题复现。
覆盖 PG 超级角色/pg_hba trust 行/对象级 PUBLIC 写授权、MySQL SUPER+转授、
MSSQL sysadmin 与角色中转 CONTROL SERVER、Oracle PUBLIC 对象授权/
GRANT OPTION/默认账号锁定。亦以生产 8 包 + 演示包的存量 findings 离线
统计生成覆盖率（在范围内的规则均为 100%）。

生成过程中的实测修正（均已回归）：PG 对象级授权的对象名取事实属性
`object`；MSSQL 服务器权限属性键为 `permission`；Oracle ANY 类权限证据
含 cdb_sys_privs 来源；pg_hba 指导文案按问题类型分别构造（改认证方式 /
收窄地址）。

## 二期覆盖（M15-2，OS/中间件 30 条）

分级口径：一期同理分精确型（mode/ACL 当前值捕获）、改名型（Tomcat 应用
mv 停用）、指导型（运行账号、TLS 证书、控制台类——切断点是现场决策）。

- Linux：sudo 两条为「整文件备份 → 按行定位编辑 → visudo 校验 → 备份
  还原」模式（NOPASSWD 为摘除标记、sudo_all 为整行注释）；服务文件可写
  为 chmod 精确对；高能力为 setcap 对（回滚按能力名集合重建 +ep，注记
  了与原始 permitted/inheritable 精细区分的边界）；身份不一致为指导型。
- Windows：本地管理员为 Remove/Add-LocalGroupMember 对（内置
  Administrator 附特别注记）；服务二进制可写为「icacls /save 快照 →
  回收写授权 → /restore 回滚」模式（快照步骤不可省略）；服务身份不
  一致为指导型（sc.exe 双向命令都给出）。
- Tomcat：部署类 mv 对；console_admin 为 tomcat-users.xml 备份 + sed
  摘除角色；连接器/TLS 为备份先行的指导型；config_writable 为 chmod 对。
- Nginx:ssl_protocols/autoindex 为定位文件后的 sed 对（含备份）；明文
  监听指导型（443+跳转或回环限定——回环绑定经实测可被规则豁免）。
- WebLogic：配置可写 chmod 对；其余三条为 WLST 指导型（生产模式、控制
  台目标收敛、关明文监听）。
- IIS:appcmd 精确对（应用池身份、匿名开关、默认站 stop/start）；明文
  绑定为证书就绪前提下的绑定增删对。
- 附带补齐一期遗漏的 db.mysql.name_resolve_on（SET PERSIST 家族）。

至此 59 条规则全部有脚本生成器。报告生成时会把实例上下文事实
（*.instance）附加给生成器，使 Tomcat/Nginx 脚本落到确切 home/配置
路径而非环境变量占位。

二期实证：Tomcat/Nginx 夹具完整闭环（6/4 条 FAIL → 修复 → 0 → 回滚
→ 复现）；WebLogic 目录夹具验生成 4/4（沿用 M7-2 边界，无在线域）；
Linux 三项在 Docker 测试容器 medaudit-test-m15os（systemd 镜像，
kf7）内完成活体闭环：sudo_nopasswd_all（摘 NOPASSWD → 0 → 回滚
→ 1，visudo 校验）、high_capabilities（setcap -r + 服务重启 → 0 →
回滚重授 → 1）、writable_service_file（chmod 0755 → 0 → 0777
→ 1）；容器保留植入态供查看。闭环中发现并修复一处生成器缺陷：
writable_service_file 取证据事实的方式错误导致从不生成脚本
（0.16.1-m15p2 已含修复；修复前报告对该规则计为程序性整改属实）。
Windows/IIS 于 win2019-test（medaudit.local 域控）完成活体闭环
（M9 WinRM 远程采集复采验证）：应用池身份 LocalSystem→
ApplicationPoolIdentity→回滚（1→0→1）、HIS 站匿名关→开
（1→0→1）、默认站点删除→appcmd 配置备份还原（1→0→1，还原后
IIS 6 条 FAIL 全量复原）、测试域用户 m15win 的管理员摘除/加回
（1→0→1）；plain_binding 为指导型（证书前置）仅验生成。闭环另
修正四处生成器问题（0.16.1/0.16.2）：writable_service_file 取
证据事实方式错误从不生成脚本；IIS 应用池名误带 apppool: 前缀；
default_site 原脚本只停站、而规则按站点存在判定（采集器只读
配置、无运行状态事实），改为删除+add backup/restore 回滚；
unexpected_admin 在域控上不可用 LocalGroupMember（无本地 SAM
组），脚本改为按 DomainRole 分支（域控走 ADGroupMember、成员
机走 LocalGroupMember）。另注：OS 采集器的服务级采集依赖目标机
systemctl（ReadUnit），无 systemd 的容器只能做基础采集（sudo/
passwd），服务类规则须在 systemd 环境下验证。域控上的测试账号
m15win（禁用态，口令复杂度未过为测试口令）与 appcmd 备份
M15-DefaultSite 保留在 VM 内。

**顺带发现（采集器边界，另行候选）**：Tomcat 采集器的 ssl_protocol 只
解析连接器上的 `SSLProtocol` 属性；Tomcat 9 常见的 SSLHostConfig
`protocols` 写法与老式小写 `sslProtocol` 都未解析，这类配置下
tls_weak 不会命中——建议后续给采集器补 SSLHostConfig 解析。

## 现场植入物（测试环境，保留供查看）

- PG16 容器：角色 m15_pg（SUPERUSER，已回滚至植入态）、表 public.m15_t、
  pg_hba 首部 `# m15-trust` 的 172.16.0.0/12 trust 行（已回滚至 trust）。
- MySQL80 容器：用户 m15_u@%（SUPER + GRANT OPTION，植入态）。
- MSSQL19 容器：登录 m15login（sysadmin 成员 + 经角色 m15_mid 持
  CONTROL SERVER，植入态）。
- ARKPDB1：沿用 M13 植入物（HISAPP.PAT_RECORDS 的 PUBLIC 授权与
  GRANT OPTION、DBSNMP OPEN），M15 闭环后已回滚恢复原样。
