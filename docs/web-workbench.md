# Web 工作台（M6，0.4.0-m6）

## 类别模型

工作台按资产类别组织审计对象（kind 前缀决定类别）：

| 类别 | kind | 审计方式 |
|---|---|---|
| 数据库 | db-oracle / db-sqlserver / db-mysql / db-postgres | **一键审计**（服务端真采集）或上传事实包 |
| 操作系统 | host / service | 目标机运行采集器回传，或上传事实包 |
| 中间件 | mw-tomcat / mw-weblogic / mw-nginx / mw-iis / mw-other | **仅登记**（专用采集器未开发，候选 M7） |
| 业务接口 | api | 采集端 apicheck 回传报告，页面查看 |

早期导入自动生成的资产 kind=unknown，工作台有「待分类资产」区可一键归类。

标准流程：类别页登记目标 → 审计 → 自动评估 → 报告页/审计结果处下载 Word 报告。

## 一键审计（数据库）

- 登记时只保存非机密连接参数（host/port/user/dbname|service/sslmode）到 assets.labels 的 JSON。
- **口令永不落库**：审计弹窗输入，仅经子进程环境变量（password_env 机制）传给采集器，配置文件不含口令，临时目录用后即删。
- 服务端以子进程调用 medaudit-collector（路径：环境变量 MEDAUDIT_COLLECTOR_BIN，未设时取服务二进制同目录），流程：采集 → 导入（含证据加密）→ 评估（可选基线）→ 生成报告，接口 POST /api/v1/audit/run，串行执行，超时 5 分钟。
- Oracle 采集走纯 Go 驱动（go-ora），无 Instant Client 依赖。

## M6 新增/变更接口

- GET/POST /api/v1/hospitals；POST /api/v1/assets（支持 labels）；PUT /api/v1/assets/{id}（修正登记与连接参数）
- GET /api/v1/bundles/{id}/facts?kind=&offset=&limit=（事实明细浏览）
- POST /api/v1/audit/run（一键审计）
- POST /api/v1/findings/{id}/retest、GET .../retests（复测：同资产新包技术口径重评估比对）
- GET/POST /api/v1/findings/{id}/remediations（整改记录）
- GET /api/v1/reports（列表）；GET /api/v1/reports/{id}/csv（问题清单 CSV，UTF-8 BOM）
- GET /api/v1/baselines 响应补 spec 字段
- GET /api/v1/assets 响应补 hospital_id 与 labels

## 前端结构

单页多视图（Vue 3，无路由/组件库新依赖）：工作台 / 数据库 / 操作系统 / 中间件 / 业务接口 / 事实包 / 问题 / 报告 / 基线 / 规则。
问题页集成复核（确认/误报/例外）、整改登记与复测执行的历史闭环。

## 已知边界

- 中间件仅登记：其进程/服务/文件权限包含在所在主机的 OS 采集中；专项核查需 M7 专用采集器。
- 操作系统不能从服务端远程采集（采集器须在目标机以管理员/root 运行），页面提供回传命令与上传入口。
- 业务接口报告暂不提供 Word 导出（页面查看 + JSON 存档）；Word 针对数据库/操作系统审计报告。
- 一键审计时目标库口令经页面传输到本机服务（同机回环），生产部署应置于 HTTPS/内网管理区之后（与平台无鉴权的既有边界一致）。
