# MedAudit

[English](README_EN.md)

面向医疗行业的**权限审计平台**：对数据库、操作系统、中间件和 HTTP API
四类对象做只读权限采集与规则评估，找出「谁拥有什么权限、哪些权限有问
题、应该怎么改」，并以专业 Word 报告完成「审计 → 整改 → 复检」的闭环。

- **服务端 `medaudit-server`**：单院部署的审计平台（Web 工作台 + 报告
  生成 + 规则/基线管理），一份部署服务一家医院。
- **采集器 `medaudit-collector`**：在目标侧或远程只读采集权限事实，打包
  为可验证的事实包；采集全程只读，不改目标系统。
- **工程师 CLI `ma` 命令族**：HP-UX LVM 风格的一命令一事（`maaudit`、
  `mafind`、`mareport`、`mabasels` …），供实施工程师在命令行完成全部
  工程师侧操作。

## 快速开始

```
# 1. 安装（Debian 系）—— RHEL 系用对应的 .rpm 与 dnf
sudo apt install ./medaudit_0.25.0+m23-1_amd64.deb

# 2. 填写本站医院（首次启动自动登记），然后重启服务
sudo vi /etc/medaudit/medaudit.env     # MEDAUDIT_SITE_HOSPITAL_ID / _NAME
sudo systemctl restart medaudit-server

# 3. 浏览器打开 http://<服务器>:8080 ，初始账号 admin（首登强制改密）
#    在「数据库 / 操作系统 / 中间件」页对对象点「开始审计」，再「导出报告」
```

## 审计对象与规则

| 类别 | 对象 | 说明 |
| --- | --- | --- |
| 数据库 | Oracle、MySQL、SQL Server、PostgreSQL | 账号、角色、系统/对象权限、口令策略、远程访问等 |
| 操作系统 | Linux、Windows、HP-UX | 账号与提权面、服务与启动项、关键文件权限等 |
| 中间件 | Tomcat、Nginx、IIS、WebLogic | 管理面暴露、运行账号、配置基线等 |
| API | HTTP API（OpenAPI 驱动） | 认证与越权类检查（apicheck 26 项） |

当前内置 **65 条规则**。评估结论区分 PASS / FAIL / UNKNOWN /
NOT_RUN / NOT_APPLICABLE——证据不足时如实报 UNKNOWN，绝不把缺失证据
折算成「通过」。除单机规则外，平台还做**关联分析**：跨对象的权限图与
提权路径求解、有效权限计算、跨期漂移对比。

现场确有业务必需的权限可通过**基线**豁免（问题页一键「加入基线」，逐项
推导、留痕）；某条检查在本站整体不适用时可由工程师**按规则停用**（必填
原因，停用后报告中不再体现）。

## 支持的平台

**服务端**（medaudit-server 运行环境）：

| 发行版系 | 包 | 备注 |
| --- | --- | --- |
| Debian 系（Debian、Ubuntu） | deb | systemd 单元，开机自启 |
| RHEL 系（RHEL、Rocky、AlmaLinux、CentOS） | rpm | 同上 |
| 其他 Linux | 源码编译 | `go build` 后自备 systemd 单元 |

当前预编译包为 x86_64。审计 Oracle 需要目标侧可达的 Oracle Instant
Client（平台不打包分发，配置项 `MEDAUDIT_ORACLE_LIB` 指向本机已安装
目录）；其余数据库走纯 Go 驱动，无此要求。

**审计对象**不要求安装任何代理：数据库走原生协议只读查询；Linux /
HP-UX 走 SSH 只读命令集；Windows 走 WinRM 推送同版本采集器一次性执
行；中间件走 SSH 远程或本地目录采集；API 走 HTTP(S) 只读探测。

## 安装

**方式一：装 Release 包（推荐）**：在 GitHub Release 页面下载对应系
统的 `.deb` / `.rpm` 直接安装。安装自动完成：建系统用户 `medaudit`、
生成证据加密密钥（写入 `/etc/medaudit/medaudit.env`，请备份，丢失则
历史证据不可读）、注册并启动 systemd 服务。两个包均为零外部依赖
（Go 静态二进制；不依赖目标机预装运行时）。

**方式二：源码编译**：

```
cd web && npm ci && npm run build && cd ..       # 前端（产物在 web/dist）
go build -o bin/ ./cmd/medaudit-server ./cmd/medaudit-collector ./cmd/ma
./package.sh 0.25.0-m23                          # 组装发行树（可选）
```

安装后的目录布局：程序 `/opt/medaudit`，配置 `/etc/medaudit/medaudit.env`，
数据 `/var/lib/medaudit`（SQLite 平台库与证据），CLI 经 `/usr/bin/ma*`
软链可用。详细部署与验收步骤见 `docs/operations-guide.md`。

## 发版

版本号形如 `0.25.0-m23`。打 tag `v<版本号>` 并推送后，由维护者构建
deb/rpm 并挂到对应 GitHub Release（打包脚本见 `packaging/`）。

## 用法速览

**客户在 Web 上只做两件事**：对对象点「开始审计」，把「导出报告」的
Word 报告发给系统负责人；整改后再次审计，在「复检对比」里确认问题
已修复 / 仍存在 / 新增。

**工程师用 `ma` 命令族**（`ma` 本身打印命令索引）：

```
malogin                                  # 登录（会话存 ~/.medaudit/session.json）
mause h-demo                             # 切换当前医院上下文
maassetls                                # 看登记的审计对象
maaudit db-mysql-01 -e MYSQL_PW          # 对一个对象审计（口令经环境变量，不落库）
mafind -c FAIL                           # 看问题（可按规则/对象过滤）
maeval <包ID> -b bl-vendor               # 用基线重评
mareport db-mysql-01 -o report.docx      # 导出 Word 报告
marulels                                 # 规则与本站启停状态
masrv                                    # 服务端状态
```

完整命令手册见 `docs/cli-guide.md`，端到端操作手册见
`docs/operations-guide.md`。

## 配置

全部配置在 `/etc/medaudit/medaudit.env`：平台库路径、采集器路径、显
示时区（`MEDAUDIT_DISPLAY_TZ`，默认 Asia/Shanghai；时间一律以 UTC
存储、按此时区渲染）、本站医院（`MEDAUDIT_SITE_HOSPITAL_ID` /
`_NAME`）、证据密钥、Oracle 客户端库路径等。改后
`systemctl restart medaudit-server` 生效。

## 工作原理

1. 采集器以**只读**方式连接目标（数据库只读查询、SSH 只读命令、WinRM
   一次性推送、API 只读探测），把权限事实连同采集收据打包为事实包；
   采不到的项在收据中如实标注，执行状态区分 COMPLETE / PARTIAL /
   FAILED。
2. 平台把事实包入库存档（证据经 AES-256-GCM 加密），规则引擎对事实
   做评估，结论与证据一一对应、可回溯到事实 ID。
3. 关联引擎在单包事实之上构建权限图，求解提权路径与有效权限；跨期
   对比给出漂移与复检结论。
4. 报告以评估快照生成 Word 文档：问题、风险、整改说明、证据摘要齐
   全；基线豁免与规则停用在报告口径中如实生效。

## 安全注意事项

- 采集全程只读：不写目标系统、不改权限、不读业务表数据；采集身份与
  平台身份分离，建议为每个目标建专用低权限采集账号。
- 审计口令**不落库**：Web 一键审计时口令只经页面进入采集子进程环境；
  CLI 口令经环境变量或交互输入，同样不持久化。
- 初始管理员口令为产品公开默认值，**首次 Web 登录强制改密**；部署后
  请第一时间完成改密。
- `/etc/medaudit/medaudit.env` 含证据密钥，权限 0640，请纳入备份并
  妥善保管。
- 平台会话为内存态，服务重启后需重新登录（属预期行为）。

## 限制

- HP-UX 采集已按命令回显夹具全量验证，真实 HP-UX 主机实采待现场条件
  （其余对象类型均已在真实环境端到端验证，见下表）。
- Oracle 大库的 `tab_privs` 采集有 5000 行窗口，超出时事实包如实标注
  PARTIAL，不静默截断。
- WebLogic 采集为目录级（config.xml 等配置工件），不连管理域运行时。
- Windows 远程审计需要被审计机能回连平台 `server_url` 拉取一次性
  采集令牌。
- 离线评估（`maoffeval`）不应用本站规则停用口径，与在线评估的区别在
  手册中明示。

## 测试记录

以下均为真实环境验证（实验室，2026-10）：

| 对象 | 场景 | 结果 |
| --- | --- | --- |
| Oracle 19c | CDB 全量采集 8528 条事实并评估 | 完成，基线豁免口径核对一致 |
| MySQL 8.4 / 8.0 | 采集、评估、基线一键豁免全流程 | 完成 |
| SQL Server 2022 | 采集 313 条事实并评估 | 完成 |
| PostgreSQL 16 | 采集、评估、基线 | 完成 |
| Windows Server 2019（域控） | WinRM 远程审计 1169 条事实 | 完成 |
| Linux（Debian 12） | 本地 + SSH 远程采集，服务枚举 | 完成 |
| HP-UX | 命令转录夹具金值验证（8 项植入问题精确命中） | 通过（真机待验） |
| Tomcat 9 / Nginx | 容器内本地采集 | 完成 |
| IIS / WebLogic | 远程审计 / 配置工件审计 | 完成 |
| API（apicheck） | 26 项检查与金值比对 | 完成（PASS 19 / FAIL 6 / NOT_RUN 1） |
| deb / rpm 安装包 | Debian 12 实机与 Rocky 9 容器安装、启停、卸载 | 通过 |

## License

MedAudit 采用 **Business Source License 1.1** 发布（源码可见，非开
源许可证）：个人使用与非生产用途（评估、测试、开发、实验室）免费；
营利性组织的生产使用需事先取得商业授权。许可方为厦门维讯信息科技
有限公司，商业授权联系：**sales@xmweixun.com**。

详见 [LICENSE](LICENSE)、[LICENSING.md](LICENSING.md) 与
[COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)。
