# M8 深化（2026-10-21，用户「深度做深一些」批准 M8-1→M8-4 全套）

## M8-1 跨层权限路径关联（internal/correlation）
同医院多事实包建权限图（主体/文件/实例节点；成员、sudo、可写、控制实例、运行身份边，均带事实证据），
BFS 搜索低权主体→root/SYSTEM/DB 超级角色的最短路径（≤5 跳）。平台：迁移 006 correlation_reports +
POST/GET /api/v1/correlations（跨医院拒绝）；Web「关联分析」页。
采集增强：Linux 新增 /etc/passwd、/etc/group 身份与成员事实；中间件文件事实补组名。
实证：kf7 植入两条链（tomcatops 组写 Tomcat conf→控制实例→root 运行；nurse1 sudo→root）全命中；
两处误报已修（只读控制台角色不建边、sudoers 缺失标记不建边）；切断后路径归零。
Oracle 双包：PDB_DBA_TEST→DBA 及 3 条两跳嵌套路径命中；SYS/SYSTEM 不作路径源。

## M8-2 有效权限求解 + AD DS 域
求解器 internal/rules（BuildEffectiveIndex/RolesOf/PrivilegesOf）：角色边传递闭包，含见证路径与证据。
规则改造：db.mysql.global_admin v2（角色派生 SUPER 命中）、db.mssql.sysadmin v2、
db.mssql.control_server v2（经服务器角色派生命中）；PG 角色属性按 PG 语义不继承（仅对象权限入闭包）。
平台：GET /api/v1/bundles/{id}/effective + Web 事实包页「有效权限」。
实证：MySQL m8_via@% 经 m8_admin_role 间接 SUPER 被判出（旧规则漏报）；MSSQL m8login 经 m8_mid 间接 CONTROL SERVER 被判出。
注：SQL Server 固定服务器角色不允许嵌套用户定义角色（服务端限制），故 sysadmin 侧以组登录为现实间接路径。
域：win2019-test 提升为 medaudit.local 域控（AD DS+DNS，DSRM 口令存 kf7 win2019.env）。
Windows 采集新增 win.domain_group_enum（NetGroup 枚举域全局组与成员，含嵌套）；未加域时记 unsupported 不算失败。
跨层实证：nurse.deng(域用户) → HIS-DBA(域全局组) → 组登录 MEDAUDIT\HIS-DBA → sysadmin 四跳路径命中。

## M8-3 数据库服务端配置审计（新模板+13 规则，规则总数 42→55）
PG：pg.hba（pg_hba_file_rules）/pg.settings 模板；规则 hba_trust(高)/hba_weak_method/hba_open_network/
password_encryption_weak/listen_all。实证：镜像默认 trust 行与植入行全命中、md5 与全网开放命中。
MSSQL：mssql.server_config（sys.configurations）；规则 xp_cmdshell(高)/clr_enabled/cross_db_chaining/adhoc_distributed。
实证：clr_enabled 命中；本夹具为 Express 版，xp_cmdshell 服务端不可启用（环境边界），其余配置项值采集正确、0 值不误报。
MySQL：mysql.server_config（global_variables 子集）；规则 local_infile/general_log_on/name_resolve_on。
实证：前两项植入命中；本容器 skip_name_resolve=ON 故第三项正确沉默。
Oracle：ora.profiles（DBA_PROFILES 口令类）；规则 profile_password_policy。
实证：DEFAULT 的 PASSWORD_REUSE_MAX/TIME=UNLIMITED 命中，其余有限值不误报。

## M8-4 漂移与趋势
漂移：GET /api/v1/bundles/{id}/drift?against={id}——同资产同适配器两包对比，
仅比权限语义稳定事实（授权/角色/身份/配置/文件权限/服务，剔除 pid/boot_id 等易变属性），
输出新增/消失清单与「新增授权+角色关系」重点计数。Web 事实包页「漂移对比」（自动取上一包）。
实证：MySQL80 前后两包对比 17 新增/0 消失/5 重点（M8-2 植入的角色链+SUPER、M8-3 配置项全抓到）。
医院汇总：GET /api/v1/summary/hospitals（资产/包/FAIL 总数/未闭环 FAIL/UNKNOWN/关联路径数）+ Web 工作台汇总卡。

生产版本 0.8.0-m8；安装包 medaudit-0.8.0-m8.tar.gz。
