# MedAudit V1 支持矩阵

## 操作系统目标

| 目标 | 主验收 | 状态 | 说明 |
|------|--------|------|------|
| Linux（systemd） | ✅ | 已验证 | kf7 实测：cron.service 10 facts / COMPLETE |
| Windows Server 2019 | ✅ | ✅ 已验证 | KVM 虚机 win2019-test 实测：1086 facts / COMPLETE；含 SQL Server 2019 Express + Windows 认证采集。用户 2026-10-20 决定：以 2019 作为 Windows 主验收平台（替代 2022） |
| Windows Server 2022 | — | 未验证 | 用户 2026-10-20 决定以 2019 替代主验收，不再等待 ISO；如未来提供 ISO 可补测 |

## 数据库目标

| 目标 | 主验收 | 状态 | 说明 |
|------|--------|------|------|
| MySQL 8.4 | ✅ | 已验证 | 362 facts / COMPLETE；部分回收/角色边覆盖 |
| MySQL 8.0 | 兼容项 | ✅ 已验证 | 8.0.46 容器：332 facts / 8 收据 / COMPLETE（SHOW GRANTS 解析兼容） |
| SQL Server 2022 | ✅ | 已验证 | 306 facts / COMPLETE；DENY 原样保留 |
| SQL Server 2019 | 兼容项 | ✅ 已验证 | 2019 容器：260 facts / 7 收据 / COMPLETE（与 2022 同量级，7 模板全跑） |
| Oracle 19c | ✅ | 已验证 | 6246 facts / PARTIAL（5000 行上限诚实截断）；CDB 普通用户 6204 facts / PARTIAL |
| PostgreSQL 16 | M4 新增 | ✅ 已验证 | 16.15 容器：67 facts / 8 收据 / COMPLETE（低权专用账号）；对象级 ACL 仅覆盖连接库，集群角色/库级为全量 |
| Oracle 11g | 非目标 | 未验证 |  kf03 有 11g 容器，仅作环境备用 |

## 认证方式

| 方式 | 状态 |
|------|------|
| MySQL 用户名/口令 | ✅ 已验证 |
| SQL Server SQL 登录 | ✅ 已验证 |
| SQL Server Windows 身份验证 | ✅ 已验证 | win2019-test + SQL 2019 Express，NTLM（工作组本地账号）：59 facts / 4 收据 / COMPLETE；驱动 go-mssqldb v1.11.2，connString net/url 转义 |
| Oracle 用户名/口令（EZCONNECT） | ✅ 已验证 |
| Oracle OS 认证 | 仅测试环境建用户时使用，非采集路径 |

## 采集器平台

| 采集器 | Linux 二进制 | Windows 二进制 |
|--------|--------------|----------------|
| os 采集 | ✅ | ✅（2019 虚机实测） |
| db-mysql | ✅ | ✅（纯 Go，可用） |
| db-sqlserver | ✅ | ✅（纯 Go，可用） |
| db-oracle | ✅ | ❌ 不支持（godror 无 Windows 构建，需用 Linux 采集器） |
| db-postgres | ✅ | ✅（纯 Go lib/pq，可用） |

## 规则覆盖

| 目标 | 规则数 | 说明 |
|------|--------|------|
| os-linux | 3 | root_mismatch / high_capabilities / writable_service_file |
| os-windows | 3 | svc_account_mismatch / writable_service_binary / unexpected_admin |
| db-mysql | 2 | global_admin / grant_option |
| db-sqlserver | 2 | sysadmin / control_server |
| db-oracle | 3 | dba_role / sysdba_pwfile / any_privilege |
| db-postgres | 4 | superuser / dangerous_role_attrs / public_db_create / public_writable |

## 平台组件

| 组件 | 状态 | 说明 |
|------|------|------|
| 平台元数据库（SQLite） | ✅ 已验证 | M5（2026-10-20）由独立 MySQL 改为嵌入式 SQLite 单文件：部署更轻，备份恢复为文件级。属对方案 V1.1「平台元数据用 MySQL」约定的决策性偏离，记录见 docs/sqlite-migration.md；MySQL 作为被核查目标的支持（上表）不受影响 |

## 中间件（M7-1，2026-10-20）

| 产品 | 状态 | 证据 |
|---|---|---|
| Tomcat 9.0.85 | ✅ 已验证 | 夹具三阶段：植入 8 FAIL 全命中 → 容器运行 run_as_root 命中 → 收紧 0 FAIL |
| Nginx（配置解析） | ✅ 已验证 | 夹具三阶段：植入 5 FAIL 全命中 → 容器运行 run_as_root 命中 → 收紧 0 FAIL |
| WebLogic 14.1.1（域配置格式） | ✅ 已验证（目录级） | 构造域夹具：植入 5 FAIL 全命中 → 收紧 0 FAIL；无在线域实测（镜像授权限制） |
| IIS（Win2019） | ✅ 已验证（实机） | win2019-test 装 Web-Server 角色后植入 HIS 站点/ LocalSystem 池，Windows 版采集器默认路径采集，6 FAIL 全命中；配置夹具另测收紧 0 FAIL |

## M8 深化能力（2026-10-21，生产 0.8.0-m8）
| 能力 | 状态 | 说明 |
|---|---|---|
| 跨层权限路径关联 | ✅ 已验证 | OS/MW/DB 多包建图搜索提权路径；kf7 双链植入命中、切断归零；Oracle 角色嵌套路径命中 |
| 有效权限传递闭包 | ✅ 已验证 | MySQL 角色派生 SUPER、MSSQL 角色派生 CONTROL SERVER 均被判出（旧规则漏报） |
| Windows 域组展开 | ✅ 已验证（域控实测） | win2019-test 已提升为 medaudit.local 域控；域全局组与嵌套成员经 NetGroup 采集；未加域环境记 unsupported |
| DB 服务端配置审计 | ✅ 已验证 | PG hba/settings、MSSQL sys.configurations、MySQL global_variables、Oracle profiles；Express 版 xp_cmdshell 服务端不可启用（环境限制） |
| 漂移对比与医院汇总 | ✅ 已验证 | 同资产两包权限语义漂移；医院级 FAIL/未闭环/关联路径汇总 |
| 远程推送审计（SSH） | ✅ 已验证 | Linux OS 与 Tomcat/Nginx/WebLogic 中间件：推送执行→回传→评估→报告；kf03 实证 |
| 远程推送审计（WinRM） | ✅ 已验证 | Windows OS（含域组）与 IIS：exe 经一次性令牌拉取，事实包分片取回；win2019-test 域控实证 |
| API 报告 Word 导出 | ✅ 已验证 | apiaudit 报告 docx（命中清单+全量探针上限 500）；存量夹具报告实证 |
| 报告路径/漂移章节 | ✅ 已验证 | 生成时点快照口径并入 privilege_paths/drift；Oracle 路径链与 MySQL 漂移计数实证；无数据缺省不冒充 |
| 试点准备包 | ✅ 已交付 | pilot/：部署指南/操作手册/实施清单/部署自检/演示数据一键加载；空库端到端验证通过 |
