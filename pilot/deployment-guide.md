# MedAudit 部署指南（试点版，对应 0.20.0-m18）

## 1. 系统要求

**服务端（管理平台）**

- Linux x86_64（amd64），建议 2 核 / 4GB 内存 / 10GB 可用磁盘起步
- 无外部数据库依赖：平台库为本地 SQLite 文件，服务自带迁移
- 运行时依赖仅 systemd（或手工以脚本拉起）；采集器为静态二进制，无目标机运行时依赖
- 浏览器访问工作台：现代 Chrome/Edge/Firefox

**目标机（被审计对象）**

- 数据库：MySQL 8.4/8.0、SQL Server 2022/2019、Oracle 19c、PostgreSQL 16（版本矩阵见安装包 docs/support-matrix.md）
- 操作系统：主流 Linux 发行版（systemd）、Windows Server 2019（2022 以 2019 替代验证，见支持矩阵）
- 中间件：Tomcat 9、Nginx、WebLogic（域配置目录级）、IIS

## 2. 安装步骤

```bash
tar xzf medaudit-0.20.0-m18.tar.gz
cd medaudit-0.20.0-m18
sudo bash install.sh
# 按提示（如需证据加密）创建 /etc/medaudit/evidence.env（权限 600）：
#   MEDAUDIT_EVIDENCE_KEY=<base64 编码的 32 字节密钥>
#   MEDAUDIT_EVIDENCE_KEY_VERSION=1
sudo systemctl daemon-reload
sudo systemctl enable --now medaudit-server
```

安装布局：`/opt/medaudit/`（bin/web/data/docs/pilot），平台库 `/opt/medaudit/data/medaudit.db`，
systemd 单元 `medaudit-server`，服务默认监听 `127.0.0.1:8080`。

如需局域网访问，二选一（部署决策，注意暴露面）：

- 在 install 生成的单元中把 `--addr 127.0.0.1:8080` 改为内网地址后重启服务；
- 或置于反向代理之后（推荐，顺带做 TLS 与访问控制）。

## 3. 网络矩阵（按采集模式）

| 模式 | 方向 | 端口/说明 |
|---|---|---|
| 数据库一键审计 | 服务端 → 目标库 | MySQL 3306 / SQL Server 1433 / Oracle 1521 / PostgreSQL 5432（以登记端口为准） |
| 远程推送（Linux/中间件） | 服务端 → 目标机 | SSH 22；全程走会话，不要求目标机回连 |
| 远程推送（Windows/IIS） | 服务端 → 目标机 | WinRM 5985；另需目标机 → 服务端 `server_url`（拉取采集器，一次性令牌） |
| 目标机本地采集回传 | 目标机 → 服务端 | 服务端 HTTP 地址（`bundle upload --server`），或在工作台「审计记录」页手工上传 zip |
| 工作台访问 | 浏览器 → 服务端 | 8080（或反代端口） |

## 4. 目标账号矩阵（最小权限）

| 对象 | 账号要求 | 说明 |
|---|---|---|
| 数据库 | 只读审计账号 | 能读数据字典/权限视图即可；平台不改目标库任何对象。Oracle 建议专用低权用户；需跨容器视图时用 CDB 公共用户并授 CONTAINER_DATA |
| Linux 主机（推送） | 可 SSH 登录账号 | root 采集最全；普通账号可采，但受限事实记 permission_denied、执行状态 PARTIAL（口径如实） |
| Windows 主机（推送） | 可 WinRM 登录的管理员账号 | 域环境可用域账号；采集含域全局组枚举需域成员身份 |
| 中间件 | 目标机登录账号（同 OS 推送）或本地执行 | 需对安装/配置目录有读权限；Tomcat 口令与哈希刻意不采集 |

**口令处理（全模式一致）**：口令只在审计弹窗输入、仅本次会话使用，永不落库、永不落盘、永不进日志。资产登记只保存非机密连接参数。

## 5. 部署后检查

```bash
bash /opt/medaudit/pilot/smoke-test.sh http://127.0.0.1:8080
# 可选：加载演示数据熟悉动线
bash /opt/medaudit/pilot/load-demo.sh http://127.0.0.1:8080
```

再人工确认：工作台可打开并完成首次登录改口令（见第 8 节）；「规则」页 59 条；管理页显示本站信息（见第 9 节）。安装包 bin/ 另含工程师 CLI `ma` 命令族（用法见操作手册第 8 节与 docs/cli-guide.md），可在服务端本机先 `malogin` 后做 `masrv` 冒烟。

## 6. 数据与备份

- 平台库备份（首选平台自带在线备份，任选其一）：登录后调 `GET /api/v1/admin/backup`，或用 `masrvbak <备份文件>`（VACUUM INTO 一致性快照）；也可用 `sqlite3 medaudit.db ".backup backup.db"`。**切勿直接 cp 运行中的 medaudit.db 主文件**——平台库为 WAL 模式，未合并的 WAL 事务会丢失，拷出的副本是旧快照；确需文件级拷贝先停服。恢复 = 停服 → 用快照替换 medaudit.db → 启动。证据加密开启时，密钥环（evidence.env）须与库一同保管，丢密钥则证据不可解。
- 回退：保留上一版本安装包与 data 备份即可整包回退；平台库只向前迁移，不做降级迁移。
- 升级：解压新包后重跑 install.sh（覆盖 bin/web，不动 data），重启服务。

## 7. 常见问题

| 现象 | 排查 |
|---|---|
| 一键审计按钮不可用 | 服务端未配置采集器：确认 MEDAUDIT_COLLECTOR_BIN / MEDAUDIT_COLLECTOR_WIN_BIN 指向 /opt/medaudit/bin 下二进制，或二进制与服务端同目录 |
| Windows 推送报缺 server_url | 在资产登记中补目标机可达的服务地址（如 http://<服务端内网IP>:8080） |
| SSH 推送指纹不匹配 | 目标机重装/换钥后指纹变化：核对后更新资产登记的 host_key，或清空走首次接受并核对回显指纹 |
| 一键审计报 ORA-01017 | 错误尾部附中文提示即口令问题：核对登记账号的口令后重试（平台不保存口令，输错不会锁定平台侧任何状态） |
| 采集执行 PARTIAL | 多为账号权限不足或单项上限（如 Oracle 视图行数上限）；看事实包收据状态逐项定位，不要当作失败 |
| 服务起不来 | `journalctl -u medaudit-server`；常见为端口占用、evidence.env 密钥格式错误、data 目录权限 |

## 8. 登录（M12 起）

工作台需登录：默认管理员 admin / admin@123（首次登录后请立即在顶栏「修改口令」更改，至少 8 位）。会话 12 小时，服务重启需重新登录。部署自检脚本可用环境变量 MEDAUDIT_USER/MEDAUDIT_PASS 带凭据运行（smoke-test.sh / load-demo.sh）。放行面与机器通道边界见 docs/auth.md。

## 9. 本站医院初始化（M17 起）

本平台为**单院部署**：一个部署只服务一家医院。本站医院在初始化时给定，
不通过页面管理多家医院。安装后在服务端环境（systemd 单元的 Environment
或启动脚本）中设置：

- `MEDAUDIT_SITE_HOSPITAL_ID`：本站医院 ID（如 hosp-001）
- `MEDAUDIT_SITE_HOSPITAL_NAME`：本站医院名称
- `MEDAUDIT_DISPLAY_TZ`：报告（Word）时间的显示时区，IANA 名，默认 `Asia/Shanghai`；平台内部存储与 Web 接口仍为 UTC，Web 页面按浏览器本地时区显示

服务首次启动时自动创建该医院登记；之后页面（工作台进度、管理页登记表单、
基线选择）自动以本站为唯一医院，管理页显示「本站信息」而非医院登记。
变更本站信息需由工程师修改上述参数后重启服务。未设置时平台处于多院
开发/测试模式（实验室实例即如此）。
