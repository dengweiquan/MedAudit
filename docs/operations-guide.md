# MedAudit 操作文档

**部署 · 建客户 · 全类型 CLI 审计 · 报告导出**（适用版本 0.25.0-m23）

按本文顺序逐步操作即可完成一次完整交付验收。每一步都给出命令、预期输出与判读要点；末尾有勾选式检查清单与排障表。

---

## 0. 约定（先读）

- **组成**：服务端（平台 + Web）一台；工程师用命令行工具 `ma`（LVM 风格命令族，如 `ma audit`、`ma find`）；目标机采集用 `medaudit-collector`（数据库由服务端代调，OS/中间件可推送或本地运行）。
- **口令纪律**：任何口令不落盘、不进平台数据库。命令行一律经 `-e <环境变量名>` 传入，或在提示时交互输入；ma 会话文件只存服务地址、用户名、会话 Cookie 与当前医院上下文。
- **结论口径**：单项结论 PASS（通过）/ FAIL（问题）/ UNKNOWN（证据不足，不能判安全）/ NOT_RUN / N/A（不适用）；整包执行状态 COMPLETE / PARTIAL（部分模板缺失，报告会注明）/ FAILED。
- **时间口径**：平台内部存储为 UTC；Web 页面按浏览器本地时区显示；Word 报告按服务端 `MEDAUDIT_DISPLAY_TZ`（默认 Asia/Shanghai）渲染；CSV 导出为 UTC 原始值。
- **评估是追加式**：同一事实包可多次评估（如先原始口径、再选基线各评一次），页面与报告按「最新一轮」展示，不会重复计数。

---

## 1. 安装部署（服务端）

### 1.1 解包与目录

```bash
tar xzf medaudit-0.25.0-m23.tar.gz -C /opt/
mv /opt/medaudit-0.25.0-m23 /opt/medaudit
ls /opt/medaudit        # 应有 bin/ web/ docs/ pilot/
```

### 1.2 准备运行环境变量

证据加密密钥（首次部署生成一次，长期保存，丢失则历史证据不可读）：

```bash
mkdir -p /opt/medaudit/data /root/.medaudit
openssl rand -base64 32        # 输出即证据密钥，妥善保管
cat > /root/.medaudit/evidence.env <<'EOF'
MEDAUDIT_EVIDENCE_KEY=<上一步输出>
MEDAUDIT_EVIDENCE_KEY_VERSION=1
EOF
chmod 600 /root/.medaudit/evidence.env
```

### 1.3 启动

```bash
set -a; . /root/.medaudit/evidence.env; set +a
export MEDAUDIT_PLATFORM_DB=/opt/medaudit/data/medaudit.db
export MEDAUDIT_COLLECTOR_BIN=/opt/medaudit/bin/medaudit-collector
export MEDAUDIT_COLLECTOR_WIN_BIN=/opt/medaudit/bin/medaudit-collector.exe
export MEDAUDIT_SITE_HOSPITAL_ID=hosp-001
export MEDAUDIT_SITE_HOSPITAL_NAME=示例医院
export MEDAUDIT_DISPLAY_TZ=Asia/Shanghai
nohup /opt/medaudit/bin/medaudit-server \
  --web-dir /opt/medaudit/web/dist --addr 0.0.0.0:8080 \
  > /var/log/medaudit.log 2>&1 &
```

- 单院部署：`MEDAUDIT_SITE_HOSPITAL_ID/NAME` 在初始化时给定本站医院，全站只服务这一家医院。
- `--addr` 按现场网络改（实验室口径为内网地址:8080）。

### 1.4 验证与首次登录

```bash
curl -s http://127.0.0.1:8080/api/v1/health
# 预期：{"status":"ok","version":"0.25.0-m23"}
```

浏览器打开 `http://<服务器>:8080`，用默认管理员 **admin / admin@123** 登录。**首次登录会被强制修改口令**（至少 8 位），改完才能进入平台——这是预期行为，默认口令就此作废。

### 1.5 冒烟自检（可选，推荐）

安装包 `pilot/smoke-test.sh` 提供 14 项自检（健康、规则数、本站信息、规则启停等）：

```bash
cd /opt/medaudit/pilot
MEDAUDIT_SERVER=http://127.0.0.1:8080 MEDAUDIT_USER=admin MEDAUDIT_PASS=<新口令> ./smoke-test.sh
```

### 1.6 备份

```bash
ma srvbak /backup/medaudit-$(date +%F).db
```

> ⚠️ 平台库是 SQLite WAL 模式：**严禁用 `cp` 直接拷贝数据库主文件**做备份（会丢未合并事务），只用上面的备份命令（一致性快照）。

---

## 2. 工程师 CLI 准备

```bash
cp -a /opt/medaudit/bin/ma /usr/local/bin/    # 工程师 CLI 只有一个 ma，或全路径使用
ma -s http://<服务器>:8080 login admin
# 按提示输入口令；预期输出：已登录 admin（…会话存 ~/.medaudit/session.json）
ma whoami
# 预期：admin @ http://<服务器>:8080 + 当前医院行
```

- 也可用环境变量 `MEDAUDIT_USER` / `MEDAUDIT_PASS` 自动登录；注意：本机若留有过期会话文件，自动登录不会触发，先执行一次 `login` 刷新。
- 服务端重启后会话失效（内存会话），重新 `login` 即可。
- 之后所有命令可省 `-s`（会话已记住）。下文为清晰起见仍写全路径变量（$CTL 后跟功能词）：

```bash
CTL='ma -s http://<服务器>:8080'
```

---

## 3. 建客户

单院模型下「建客户」= 确认本站医院 → 建使用账号 → 登记该客户的审计对象。

### 3.1 确认本站医院

Web 打开「管理」页，顶部「本站信息」应显示部署时给定的医院。后续登记的对象自动归属本站。

### 3.2 建用户账号

```bash
export NEWPW='Field@1234'                     # 初始口令经环境变量，不写进命令历史明文亦可交互输入
$CTL useradd engineer1 -e NEWPW
$CTL userls
```

| 命令 | 用途 |
|---|---|
| `ma useradd <名> [-e <VAR>]` | 建号；新账号首次 Web 登录强制改密 |
| `ma userpw <名> [-e <VAR>]` | 重置口令，并吊销该用户全部会话 |
| `ma useroff / ma useron <名>` | 禁用/启用；禁用即吊销会话；不能禁用自己与最后一个可用账号 |
| `ma userls` | 列表（状态、强制改密标志、创建时间） |

所有账号当前同权（无角色分级）；建号/重置/启停都会在服务端日志留痕。

### 3.3 登记审计对象（资产）

数据库类（端点为位置参数：`主机[:端口]/库名`，Oracle 为服务名；端口可省用缺省；口令不在登记内容里；医院自动取上下文，单院部署即本站）：

```bash
$CTL assetadd db-oracle    10.0.0.11:1521/HISDB -u medaudit_reader -n '核心库 Oracle'   -i db-ora-01
$CTL assetadd db-mysql     10.0.0.12:3306/his   -u root            -n '门诊 MySQL'      -i db-mysql-01
$CTL assetadd db-sqlserver 10.0.0.13:1433/master -u sa             -n '住院 SQL Server' -i db-mssql-01
$CTL assetadd db-postgres  10.0.0.14:5432/lis   -u medaudit_reader -n '检验 PostgreSQL' -i db-pg-01
```

操作系统/中间件类（远程端点为位置参数：`[账号@]主机[:端口]`；复杂参数仍可用 `-f labels文件` 整体给定）：

```bash
# Linux（SSH 推送；服务清单可空，空时自动枚举运行中服务；要指定加 -s ssh.service,docker.service）
$CTL assetadd os-linux root@10.0.0.21 -n '应用服务器 Linux' -i os-linux-01

# Windows（WinRM；回连地址 -U 缺省取会话服务端地址，为目标机可达的平台地址）
$CTL assetadd os-windows 'his\administrator@10.0.0.22' -U http://<服务器>:8080 -n '域控 Windows' -i os-win-01

# HP-UX（SSH 命令采集，无二进制推送）
$CTL assetadd os-hpux root@10.0.0.23 -n '小型机 HP-UX' -i os-hpux-01

# 中间件远程型示例：IIS 走 WinRM；Tomcat/Nginx/WebLogic 走 SSH 并用 -d 给目标机上的安装/域目录
$CTL assetadd mw-iis 'his\administrator@10.0.0.22' -n '接口机 IIS' -i mw-iis-01
$CTL assetadd mw-tomcat root@10.0.0.24 -d /usr/local/tomcat -n '接口机 Tomcat' -i mw-tomcat-01
```

登记后核对：`$CTL assetls`（详情 `assetshow <id>`）。改参数用 `assetmod <id> [-n <名称>] [-u <账号>] [-f labels文件]`（只改给出的项）。

---

## 4. 按类型执行审计（CLI）

通用闭环（每类相同）：**审计 → 看问题 →（可选）基线评估 → 导报告**。

```bash
$CTL find <包ID> -c FAIL        # 问题清单（-j 输出 JSON，含 finding 数字 id）
$CTL eval <包ID> -b <基线ID>    # 选基线再评一次（厂商/内置账号豁免）
$CTL report <包ID> -o <文件名>.docx   # 生成并下载 Word 报告（见第 5 节）
```

**确认例外（基线豁免）最简路径——Web 问题页一键加入（0.24.0 起）**：打开「问题」页 → 展开问题类型 → 展开主体 → 点开一条 FAIL 明细 → 「加入基线」：系统按该问题的证据**自动推导**放行项（主体/种类/值/范围都已算好，不用手填）→ 选已有基线或新建 → 填原因 → 确认。之后评估默认自动套用本院基线，该条不再计为问题；也可点「用该基线重新评估本包」立即重评。个别检查项不支持豁免（会明确提示），整类停用请用「规则」页的规则启停。基线页已改为结构化表单（逐条填写/删除放行项），原始 JSON 仅保留在「高级」折叠区；基线页还可对整条基线编辑放行项（ID、医院、目标锁定，保存后版本 +1）或删除整条基线（已存问题与报告不动，之后的评估不再用它豁免）；工程师也可用 `ma baseexempt <finding-id>` 在命令行一键豁免（先预览推导项、确认后加入），或用 `ma baseadd -f 基线.json` 以文件方式维护基线。

### 4.1 Oracle

```bash
export ORA_PW='******'          # 采集账号口令（建议专用只读审计账号）
$CTL ma audit db-ora-01 -e ORA_PW
# 预期输出示例：
# 数据库一键审计完成：事实 8528 / 收据 10；评估 1690 条（FAIL 1630，落库 1630）；
# 报告 report-bundle-ora-…；事实包 bundle-ora-…
$CTL bundleshow bundle-ora-…
```

判读要点：
- 整包多为 **PARTIAL**：`ora.tab_privs` 模板按 5000 行窗口采集，大型生产库会标注「截断」——这是诚实口径，不是失败；对象级授权规则只覆盖窗口内数据，报告会注明。
- FAIL 大头通常是 `db.oracle.any_privilege`（厂商对象授权量级大），先用厂商基线评估区分「厂商固有」与「业务真实问题」，再看 dba_role / default_account_open 等条目。

### 4.2 MySQL / SQL Server / PostgreSQL

命令形与 Oracle 相同（`ma audit <对应资产>`），各自资产登记时给定的账号连接，口令经 `-e` 传入（或环境变量 `MEDAUDIT_PW`、或交互输入）。

```bash
$CTL ma audit db-mysql-01 -e MY_PW
$CTL ma audit db-mssql-01 -e MS_PW
$CTL ma audit db-pg-01 -e PG_PW
```

判读要点：
- **每个实例的口令相互独立**（如 MySQL 8.4 与 8.0 两台实例口令不同），1045/登录失败先核对该实例口令。
- MySQL 先看 `global_admin`（SUPER 持有者）与 `remote_no_tls`（远程账号未强制 TLS）；SQL Server 先看 `sysadmin` 成员与 `control_server`；PostgreSQL 先看 `superuser` 与 pg_hba 相关项。

### 4.3 Linux

路径 A（远程推送，资产已登记 SSH 参数）：

```bash
$CTL ma audit os-linux-01 -e SSH_PW
# 输出含主机密钥指纹（首次 TOFU 回显，请与目标机核对后可登记 labels 的 host_key 固定）
```

路径 B（在目标机或跳板机本地采集后导入）：

```bash
medaudit-collector os os-linux-01 -o linux.zip -H hosp-001 \
  [-s ssh.service,docker.service]     # 可空：空时自动枚举运行中 systemd 服务（上限 50）
$CTL bundlein linux.zip
$CTL eval <包ID>
```

判读要点：服务类检查 UNKNOWN 多半是未采到服务面——确认 `-s` 或自动枚举生效（收据里 `linux.unit_info` 应有行数）。

### 4.4 Windows

```bash
$CTL ma audit os-win-01 -e WIN_PW
# WinRM 通道：采集器 exe 由目标机凭一次性令牌从平台拉取（令牌 5 分钟单次有效）
```

判读要点：`os.windows.unexpected_admin` 看管理员组成员（含域组嵌套）；域内置结构（域管组、内置 Administrator）可经基线豁免，业务/测试账号不应豁免。

### 4.5 HP-UX

路径 A（服务端远程，资产已登记 SSH 参数）：`$CTL ma audit os-hpux-01 -e HPUX_PW`（SSH 命令采集，不推送二进制）。

路径 B（工程师本地）：

```bash
export MEDAUDIT_HPUX_PASSWORD='******'
medaudit-collector hpux root@10.0.0.23 os-hpux-01 -o hpux.zip -H hosp-001
# 或从命令转录目录回放： medaudit-collector hpux -t <dir> os-hpux-01 …
$CTL bundlein hpux.zip && $CTL eval <包ID>
```

规则共 6 条：多 UID 0、弱口令存储（普通模式）、inetd 高危服务、启动文件可写、基线外 setuid、sudo 全命令授权。

### 4.6 中间件（Tomcat / Nginx / WebLogic / IIS）

Tomcat / Nginx / WebLogic 为目录级采集（第二个参数为安装或域目录）：

```bash
medaudit-collector mw tomcat   /usr/local/tomcat        mw-tomcat-01   -o tc.zip -H hosp-001
medaudit-collector mw nginx    /etc/nginx               mw-nginx-01    -o ng.zip -H hosp-001
medaudit-collector mw weblogic /u01/domains/his_domain  mw-weblogic-01 -o wl.zip -H hosp-001
$CTL bundlein tc.zip && $CTL eval <包ID>
```

判读要点：
- **容器部署**时把采集器复制进容器内执行（`docker cp` + `docker exec`），否则进程类检查（如 run_as_root）因视角不一致为 UNKNOWN。
- WebLogic 无运行进程可看，run_as_root 类恒为 UNKNOWN，属目录级采集的既定边界。
- IIS 走远程：`$CTL ma audit mw-iis-01 -e WIN_PW`。

### 4.7 业务接口（API 越权审计）

先写配置文件（凭据只写环境变量名）：

```yaml
# apicheck.yml
base_url: http://his-app:8080
spec_url: http://his-app:8080/openapi.json     # 绝对 URL 或相对路径均可；也可用 spec_file / har_file
identities:
  - name: admin
    role: admin
    headers_env: { Authorization: TOK_ADMIN }
    owns: { user_id: "1" }                     # 该身份拥有的路径参数样本
    canary: admin@his.local                    # 只出现在其自有资源里的标记串（如邮箱）
  - name: alice
    role: user
    headers_env: { Authorization: TOK_ALICE }
    owns: { user_id: "2" }
    canary: alice@his.local
  - name: bob
    role: user
    headers_env: { Authorization: TOK_BOB }
    owns: { user_id: "3" }
    canary: bob@his.local
  - name: anonymous                            # 匿名身份（无凭据）验证公开端点
expectations:
  - { path: /api/public/health, access: public }
  - { path: /api/admin/users, access: admin_only }
  - { path: "/api/users/{user_id}", access: owner_or_admin }
```

执行并直传平台：

```bash
export TOK_ADMIN='Bearer ***' TOK_ALICE='Bearer ***' TOK_BOB='Bearer ***'
medaudit-collector apicheck -f apicheck.yml -o api-report.json -u http://<服务器>:8080
# 预期：越权检测完成：26 checks（PASS 19 / FAIL 6 / UNKNOWN 0 / NOT_RUN 1），execution=COMPLETE
#       上传结果：201 {"report_id":"apiaudit-…","status":"stored"}
```

- 写方法（POST 等）默认只登记 NOT_RUN 不实际探测；`probe_writes: true` 仅应在夹具/隔离环境开启。
- 缺 expectations 或身份 canary 时，相关检查会是 UNKNOWN（证据不足），不是 PASS。

---

## 5. 导出报告

### 5.1 常规报告（Word）

一键审计/远程审计结束时已自动生成报告；也可对任意事实包手动生成并下载：

```bash
$CTL report <包ID> -o 审计报告.docx        # 生成并下载（-o 可省，自动命名）
$CTL reportls                                   # 历史报告
$CTL reportshow <报告ID>                     # 快照摘要（问题数、脚本数、章节）
$CTL reportfix <报告ID> [-r <规则ID>] # 打印修复/回滚脚本（四步：前置检查→修复→验证→回滚）
```

- Word 结构：封面信息（对象、审计时间——显示时区）、执行摘要、问题分布、按规则的问题明细（含整改建议与证据）、提权路径/漂移/修复脚本章节（有数据才出现）、附录。
- 平台只生成脚本、**不自动执行**；由工程师评审后人工执行，回滚为生成时捕获的精确逆操作。

### 5.2 问题清单（CSV）

```bash
$CTL find <包ID> -o findings.csv   # 问题清单 CSV（finding_id/规则/主体/结论/明细；修复脚本走 ma reportfix 或报告 CSV）
```

CSV 内时间为 UTC 原始值（与 Word 的显示时区口径不同，交换数据时注意）。

### 5.3 API 报告（Word）

Web「业务接口」页对已上传的报告点「Word」，或接口下载：

```bash
curl -b <会话Cookie> -o api报告.docx \
  http://<服务器>:8080/api/v1/api-audits/<report_id>/docx
```

### 5.4 整改复检闭环

1. 把 Word 报告发给系统负责人，按报告内整改建议与修复脚本整改；
2. 对同一资产再次执行审计（同第 4 节命令）；
3. Web「复检对比」页查看 已修复 / 仍存在 / 新增 三类变化；命令行可用
   `$CTL bundledrift <新包> <旧包>` 看事实层漂移；
4. 循环直至问题清零或经基线/规则启停确认例外（规则启停在 Web「规则」页操作，须填写原因，关闭的检查项不再进报告）。

---

## 6. 验收检查清单

部署与账号
- [ ] `GET /api/v1/health` 返回 ok 且版本为 0.25.0-m23
- [ ] 默认口令已改，Web 登录后不被强制改密拦截
- [ ] `ma whoami` 正常；`ma useradd` 建出工程师账号且其首登被要求改密
- [ ] 本站医院在管理页显示正确，登记的对象都归属本站

逐类型各跑通一遍（审计 → 问题 → 报告三步齐）
- [ ] Oracle：`ma audit` 完成；理解 PARTIAL（tab_privs 截断）含义；报告可下载
- [ ] MySQL：`ma audit` 完成；global_admin / remote_no_tls 结论可解释
- [ ] SQL Server：资产已登记；`ma audit` 完成；sysadmin 成员结论可解释
- [ ] PostgreSQL：`ma audit` 完成
- [ ] Linux：`ma audit`（远程推送）或本地采集导入完成；服务类检查无 UNKNOWN（或原因明确）
- [ ] Windows：`ma audit`（WinRM）完成；管理员组结论可解释
- [ ] HP-UX：远程命令采集或转录流程完成；6 条规则均有结论
- [ ] Tomcat / Nginx：采集完成（容器为容器内采集）；控制台账号/明文监听结论可解释
- [ ] WebLogic：目录采集完成；dev_mode / console / 明文监听有结论（run_as_root UNKNOWN 为预期）
- [ ] IIS：`ma audit` 完成
- [ ] API：apicheck COMPLETE；垂直/水平越权探针有结论；报告已上传且 Word 可下载

报告与闭环
- [ ] 任选一包：`ma report` 下载的 Word 时间为本地时区、章节完整
- [ ] `ma reportfix` 能打印修复/回滚四步脚本
- [ ] 对任一资产复检一次，复检对比能分出已修复/仍存在/新增

---

## 7. 常见问题

| 现象 | 原因与处理 |
|---|---|
| ORA-01017 / 登录被拒 | 采集账号口令不对。先用同一口令在目标机验证再跑；错误信息已带中文提示 |
| MySQL 1045 Access denied | 该**实例**的口令不对（不同实例/版本口令相互独立），核对资产对应的实例 |
| ma 报「未登录或会话已过期」 | 服务端重启或会话过期，重新 `ma login` |
| 导入返回 duplicate | 包 ID 按秒生成，同秒重复导入/采集会撞 ID；间隔 2 秒重采或重导 |
| findings 条数多于本轮 FAIL | 评估为追加落库（多次评估各成一轮）；以最新一轮为准（Web 口径），或看 `evaluate` 当轮输出 |
| Oracle 整包 PARTIAL | tab_privs 5000 行窗口截断（大库常态），收据里有标注；不是失败 |
| Linux 服务类检查 UNKNOWN | 服务面未采到：登记/采集时给服务清单（资产 `-s`、采集器 `-s`），或确认自动枚举（systemd）生效 |
| 中间件 run_as_root UNKNOWN | 采集器与目标进程不在同一视角：容器场景把采集器送进容器内执行 |
| apicheck 拉取 OpenAPI 404 | 检查 `spec_url` 地址本身可达（绝对 URL 与相对路径均支持）；404 多为地址写错 |
| apicheck 大量 UNKNOWN | 配置缺 `expectations` 或身份缺 `owns`/`canary`，引擎证据不足不下结论 |
| 远程审计等待较久 | 服务端超时 8 分钟；WinRM 需目标机回连平台拉采集器，确认 `server_url` 可达 |
| 报告时间差 8 小时 | Word 看服务端 `MEDAUDIT_DISPLAY_TZ` 是否为 Asia/Shanghai；Web 看浏览器时区；CSV 为 UTC 属预期 |

---

*配套文档：`docs/cli-guide.md`（CLI 完整手册，命令与旗标全量）、`pilot/deployment-guide.md`（部署细则）、`pilot/operator-manual.md`（操作手册）、`docs/m21-hpux.md`（HP-UX 专题）。*
