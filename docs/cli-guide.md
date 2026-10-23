# MedAudit 工程师 CLI 手册（ma 命令）

**适用版本 0.28.0-m28**。Web 工作台面向客户（点审计、看问题、导出报告）；工程师的执行面是本文的 `ma` 命令——**只有一个命令 `ma`，第二个词是功能**（如 `ma assetadd`、`ma audit`、`ma find`），一功能一件事；目标（ID/端点）一律**位置参数**；选项只用**单字母短旗标**；当前医院等上下文存会话，不逐条命令重复声明。`ma` 界面语言随运行环境：中文环境（locale 以 `zh` 开头）显示中文，**其他环境显示英文**（判定顺序 `LC_ALL` > `LC_MESSAGES` > `LANG`）；服务端返回的文案原样透传、不翻译。

老 `medauditctl` 命令族自 0.25.0 起**移除**（对照表见第 7 节）；早期 0.25.0 版的 `ma*` 多调用符号链接形式（`maaudit` 等）已取消，只保留 `ma <功能>`。

---

## 0. 快速开始（5 分钟）

```bash
# 安装：把安装包 bin/ 加入 PATH（内含 ma 与 ma.exe）
ma -s http://<服务器>:8080 login admin     # 口令交互输入（不回显）；或环境变量 MEDAUDIT_PASS
ma whoami                                   # admin @ http://<服务器>:8080 + 当前医院
ma assetadd db-mysql 10.0.0.12:3306/his -u root -n '门诊 MySQL' -i db-mysql-01
ma audit db-mysql-01                        # 口令交互输入；或 -e 环境变量名 / 环境 MEDAUDIT_PW
ma find <事实包ID> -c FAIL                  # 看问题（审计输出里有包 ID）
ma report <事实包ID>                        # 生成报告并下载 Word（自动命名 report-<包ID>.docx）
```

只有一种调用形式：`ma <功能> …`。只敲 `ma` 打印全部功能索引。

---

## 1. 通用约定

### 1.1 服务端地址解析

优先级：全局 `-s <url>`（写在命令前，如 `ma -s http://srv:8080 login admin`）> 环境变量 `MEDAUDIT_SERVER` > 会话文件 > `http://127.0.0.1:8080`。

### 1.2 会话与上下文

- `ma login` 成功后会话存 `~/.medaudit/session.json`（0600）：服务地址、用户名、会话 Cookie、**当前医院**。**不存口令**。
- 当前医院（上下文）：`-h` 旗标 > `ma use <医院ID>` 设定值 > 本站医院（单院部署自动取本站，通常无需关心）。多院/实验室实例先 `ma use` 一次，后续命令（基线列表、汇总、关联自动选包等）都按此上下文工作。
- 无会话文件但环境变量 `MEDAUDIT_USER`/`MEDAUDIT_PASS` 齐备时自动登录（脚本场景）；注意本机留有过期会话文件会挡住自动登录，先 `ma login` 刷新一次。
- 服务端重启后会话失效（内存会话），重新 `ma login` 即可。

### 1.3 口令纪律

任何口令不落盘、不进平台库、不进命令行明文：

| 场景 | 来源顺序 |
|---|---|
| 平台登录 | 环境 `MEDAUDIT_PASS` > 交互输入 |
| 审计目标（ma audit/ma useradd/ma userpw） | `-e <环境变量名>` > 环境 `MEDAUDIT_PW`（仅审计） > 交互输入 |
| 批量清单/采集器 | 文件中只写环境变量名，运行时取环境 |

### 1.4 短旗标总表（全族统一）

| 旗标 | 含义 | 旗标 | 含义 |
|---|---|---|---|
| `-s` | 服务端地址（全局，置于命令前） | `-o` | 输出文件 |
| `-u` | 账号 | `-f` | 输入文件（清单/labels/基线） |
| `-n` | 名称 | `-j` | JSON 输出 |
| `-i` | 资产 ID（登记时指定） | `-c` | 结论过滤（ma find） |
| `-h` | 医院覆盖 | `-r` | 规则过滤 |
| `-b` | 基线 ID / 基线文件 | `-k` | 类型过滤（ma assetls） |
| `-e` | 口令来源环境变量名 | `-a` | 资产过滤（ma bundlels） |
| `-U` | 回连地址 server_url（WinRM 资产） | `-d` | 中间件目录（远程资产 labels 的 mw_home） |
| `-F` | 有 FAIL 时退出码 2（脚本门禁） | `-y` | 免确认（ma baseexempt） |

短旗标与位置参数可交错书写（`ma find <包> -c FAIL` 与 `ma find -c FAIL <包>` 等价）。`-h` 在本族中是「医院」，不是 help；看帮助敲 `ma`。

### 1.5 退出码

0 正常；1 执行错误；2 业务 FAIL（仅 `-F` 给出时）。

---

## 2. 功能全表

### 2.1 会话与上下文

| 命令 | 说明 |
|---|---|
| `ma login [user]` | 登录（缺省 admin 或环境 `MEDAUDIT_USER`） |
| `ma logout` | 注销并清除本地会话 |
| `ma whoami` | 当前用户、服务端、当前医院及其来源 |
| `ma use [hospital]` | 无参 = 查看上下文；有参 = 设定当前医院 |
| `ma site` | 本站医院信息（未初始化时提示多院模式） |

### 2.2 平台账号

| 命令 | 说明 |
|---|---|
| `ma userls` | 用户列表（状态、强制改密、创建时间） |
| `ma useradd <name> [-e VAR]` | 建号；新账号首登强制改密 |
| `ma userpw <name> [-e VAR]` | 重置口令（吊销其全部会话、首登强制改密） |
| `ma useroff <name>` / `ma useron <name>` | 禁用（吊销会话）/ 启用；防自锁（不能禁用自己与最后一个可用账号） |

### 2.3 医院（客户）

| 命令 | 说明 |
|---|---|
| `ma hosls [-j]` | 医院（客户）列表 |
| `ma hosadd <id> [-n 名称]` | 登记医院（客户）；名称缺省同 id。**登记资产前医院必须先登记**，否则服务端返回 400 |
| `ma hosrm <id> [-y]` | 删除医院（客户）**及其全部数据**（资产/事实包/问题/报告/基线等，单事务级联删除）：执行前列出各类数据计数，须输入医院 ID 原样确认（`-y` 跳过确认）；所删医院若为当前上下文会自动清除；**本站医院不可删**（整场清除用 `ma srvreset`）；API 审计报告无医院归属、不在此删除范围 |

### 2.4 审计对象（资产）

| 命令 | 说明 |
|---|---|
| `ma assetls [-k 类型] [-j]` | 资产列表 |
| `ma assetadd <类型> <端点> [-i id] [-n 名称] [-u 账号] [-h 医院] [-f labels文件] [-U 回连地址] [-d 远程目录] [-s 服务清单]` | 登记资产；端点语法见第 3 节；`-i` 缺省由类型+主机推导 |
| `ma assetshow <id>` | 资产详情（含 labels 参数全量） |
| `ma assetmod <id> [端点] [-n 名称] [-u 账号] [-f labels文件] [-U 回连地址] [-d 目录] [-s 服务清单]` | 修改：给端点则按新端点重建参数；只给旗标则字段级覆盖 |
| `ma assetrm <id>` | 删除登记（历史事实包/报告保留） |

### 2.5 审计执行与评估

| 命令 | 说明 |
|---|---|
| `ma audit <资产id> [-b 基线] [-e VAR] [-F]` | 一键审计：db 类走数据库通道，os/mw 类走远程推送（按资产类型自动分发） |
| `ma audit -f 清单.yaml [-F]` | 批量巡检（清单格式同旧版：asset/type/password_env/baseline） |
| `ma eval <包id> [-b 基线] [-F]` | 对已导入的包在线评估（每次评估追加一轮） |
| `ma offeval <包.zip> [-b 基线.json] [-o 报告.docx] [-j] [-F]` | 离线评估：本地同一规则引擎求值，可出离线 Word；**不应用本站规则启停**（纯技术口径） |

### 2.6 事实包

| 命令 | 说明 |
|---|---|
| `ma bundlels [-a 资产] [-j]` | 事实包列表 |
| `ma bundlein <文件.zip>` | 导入离线事实包（机器通道，免登录亦可） |
| `ma bundleshow <包id> [-j]` | 元数据、逐模板收据（含截断标注）、事实构成 |
| `ma bundledrift <新包> <旧包>` | 两包事实层漂移（须同资产同适配器） |
| `ma bundleeff <包id> [-j]` | 有效权限（传递闭包，派生权限带见证路径） |

### 2.7 问题与报告

| 命令 | 说明 |
|---|---|
| `ma find <包id> [-c 结论] [-r 规则] [-j] [-o 清单.csv]` | 问题清单；`-j` 含 finding 数字 id（豁免用）；CSV 为 UTC 原始时间 |
| `ma report <包id> [-o 报告.docx]` | 生成报告并下载 Word（-o 缺省自动命名） |
| `ma reportls` | 报告列表 |
| `ma reportshow <报告id> [-j]` | 报告快照摘要（问题数、脚本覆盖、章节） |
| `ma reportfix <报告id> [-r 规则]` | 打印修复脚本四件套（前置检查→修复→验证→回滚；平台只生成不执行） |

### 2.8 基线与规则

| 命令 | 说明 |
|---|---|
| `ma basels [-h 医院] [-j]` | 当前医院的基线列表 |
| `ma baseshow <id> [-o 文件]` | 查看/导出基线（文件即全量格式，可再 `ma baseadd` 回登） |
| `ma baseadd -f 基线.json` | 登记基线（文件缺 hospital_id 时取上下文） |
| `ma basediff <基线A> <基线B>` | 放行集差异（参数可为基线 ID 或 .json 文件） |
| `ma baseexempt <finding-id> [-b 基线] [-y] [原因…]` | 一键豁免：按问题证据推导放行项 → 预览 → 确认 → 加入基线。`-b` 指定基线（存在则追加、不存在则新建）；缺省时唯一同目标基线自动选、无则新建 `bl-exempt-<目标>`。不支持豁免的规则会明确提示（改用 ma ruleoff 整类关闭） |
| `ma rules [-j]` | 规则清单与本站启停状态（含关闭原因留痕） |
| `ma ruleoff <规则id> <原因…>` | 关闭检查项（本站作用域，原因必填并留痕；关闭项不计结果、不进报告） |
| `ma ruleon <规则id>` | 恢复检查项 |

基线与规则启停的分工：基线 = 对**具体主体**的已知例外（厂商/内置账号）；规则启停 = 对**整条检查项**的本站停用。基线只在评估时选用才生效（`ma audit -b` / `ma eval -b`）。

### 2.9 关联、汇总、服务端

| 命令 | 说明 |
|---|---|
| `ma corr [包id…]` | 跨包提权路径分析；无参时自动取当前医院各资产最新包（2–12 个） |
| `ma sum` | 医院风险汇总（有上下文时只显示当前医院） |
| `ma srv` | 服务端状态（健康、版本、当前会话用户） |
| `ma srvbak <备份文件>` | 平台库在线备份（VACUUM INTO 一致性快照，0600 落盘并打印 sha256）。恢复 = 停服 → 以快照替换平台库文件 → 启服。**切勿直接 cp 运行中的库主文件**（WAL 模式会丢未合并事务） |
| `ma srvreset [-o 备份文件] [-y]` | **一键清场**（新客户现场交接）：先在线备份到本地文件（缺省名 `medaudit-before-wipe-<时间>.db`，备份失败即中止），输入 `WIPE` 确认后（`-y` 跳过）清除全部医院/资产/事实包/问题/报告/基线/规则启停/用户数据；用户恢复默认 admin（`admin@123`，首登强制改密）、全部会话吊销、本站医院按配置重登记；许可文件与服务端配置不动。清场后用 `ma hosadd` 登记新客户即可开工 |

---

## 3. 资产端点语法（ma assetadd 第二个参数）

| 类型 | 端点形式 | 例 |
|---|---|---|
| db-oracle | `主机[:1521]/服务名` | `10.0.0.11:1521/HISDB` |
| db-mysql / db-sqlserver / db-postgres | `主机[:端口]/库名`（端口缺省 3306/1433/5432） | `10.0.0.12/his` |
| os-linux / os-hpux | `[账号@]主机[:22]`（SSH） | `root@10.0.0.21` |
| os-windows / mw-iis | `[账号@]主机[:5985]`（WinRM；回连地址缺省取会话服务端，`-U` 覆盖） | `'his\administrator@10.0.0.22'` |
| mw-tomcat / mw-nginx / mw-weblogic（远程） | `[账号@]主机[:22]` + `-d <目标机安装/域目录>` | `root@10.0.0.24 -d /usr/local/tomcat` |
| mw-*（本地目录） | 目录绝对路径（以 `/` 开头） | `/u01/domains/his_domain` |
| 任意（仅导入用） | `-`（无连接参数；用 `-i` 指定 ID） | `-` |

账号也可统一用 `-u` 给出（端点内账号优先）。服务清单（os 类）用 `-s ssh.service,docker.service` 写 labels，缺省在审计时自动枚举运行中服务。复杂/历史参数仍可用 `-f labels.json` 整体给定（与旧版 labels 文件格式相同）。

---

## 4. 采集器（medaudit-collector）

与 ma 同步简化：位置参数 + 短旗标，医院可用环境 `MEDAUDIT_HOSPITAL` 缺省，输出缺省自动命名，长旗标继续可用。

```bash
medaudit-collector db -f <配置.yml> [-o 输出.zip] [-P]        # 引擎取配置内 engine；-P 预检（退出码 0 完整/3 不完整/1 失败）
medaudit-collector os [资产id] [-o 输出.zip] [-s a.service,b.service] [-H 医院]
medaudit-collector mw <tomcat|nginx|weblogic|iis> [目录] [资产id] [-o 输出.zip] [-H 医院]
medaudit-collector hpux <user@host[:port]> [资产id] [-e 口令环境变量] [-o 输出.zip] [-H 医院]
medaudit-collector hpux -t <转录目录> [资产id] [-o 输出.zip]
medaudit-collector apicheck -f <配置.yml> [-o 报告.json] [-u 上传地址]   # 上传地址缺省读环境 MEDAUDIT_SERVER
medaudit-collector bundle verify <文件.zip>
medaudit-collector bundle upload <文件.zip> [服务地址]
```

db 配置 YAML、apicheck 配置 YAML 的字段与旧版相同（凭据只写 `password_env` 环境变量名）。

---

## 5. 典型工作流

### 5.1 日常巡检（联网、批量）

```bash
ma login
ma audit -f inventory.yaml -F     # 清单逐项给 asset/type/password_env/baseline；任一 FAIL 退出码 2
```

### 5.2 现场单机审计 + 出报告

```bash
ma assetadd db-oracle 10.0.0.11:1521/HISDB -u reader -n 核心库 -i db-ora-01
ma audit db-ora-01 -e ORA_PW
ma find <包ID> -c FAIL
ma baseexempt <finding-id> -y 厂商维护账号    # 个别例外一键入基线
ma eval <包ID> -b <基线ID>
ma report <包ID>
```

### 5.3 隔离现场（无内网）

```bash
medaudit-collector db -f db.yml -o bundle.zip        # 目标侧采集
ma offeval bundle.zip -o 离线报告.docx                # 本地评估出 Word（不应用规则启停）
# 回到联网环境后： ma bundlein bundle.zip && ma eval <包ID>  （在线口径为准）
```

### 5.4 整改复核（闭环）

整改后对同一资产再 `ma audit`，用 `ma bundledrift <新包> <旧包>` 看事实层变化；销账口径以 Web「复检对比」为准。

### 5.5 例外对齐（新到一家现场）

先原始口径审计 → 对厂商/内置账号类问题逐条 `ma baseexempt`（或 Web 问题页一键加入）→ `ma eval -b <基线>` 复评 → 剩余 FAIL 即真实待整改项。

---

## 6. 常见错误与处理

| 现象 | 处理 |
|---|---|
| 未登录或会话已过期 | 服务端重启/会话过期 → `ma login`；注意过期会话文件会挡环境变量自动登录 |
| 未设定当前医院 | 多院实例先 `ma use <医院ID>`；单院部署自动取本站不会出现 |
| 环境变量 X 未设置 | `-e` 指定的变量名在本机环境不存在；export 后重试（口令不要写进命令明文） |
| bundle 已导入（同秒碰撞） | 包 ID 为秒级分辨率；ma audit 已自动等 2 秒重试一次，导入场景手动间隔 2 秒 |
| 漂移对比报「只能对比同一资产」 | 换同资产的两个包 |
| ma basediff 提示基线不存在 | 上下文医院不对：`-h` 指定或先 `ma use`；跨院基线先 `ma baseshow -o` 导出文件再按文件比 |

---

## 7. 旧命令对照（medauditctl → ma，0.25.0 起旧命令移除）

| 旧 | 新 | 旧 | 新 |
|---|---|---|---|
| `login/logout/whoami` | `ma login/ma logout/ma whoami` | `bundle list/import/show/drift/effective` | `ma bundlels/in/show/drift/eff` |
| `user create/list/reset-password/disable/enable` | `ma useradd/ls/pw/off/on` | `findings --bundle B` | `ma find B` |
| `audit db/remote --asset A` | `ma audit A`（自动分发） | `report --bundle B --docx f` | `ma report B -o f` |
| `audit batch --inventory f` | `ma audit -f f` | `report list/show/scripts` | `ma reportls/show/fix` |
| `evaluate --bundle B` | `ma eval B` | `asset create/update/delete` | `ma assetadd/mod/rm` |
| `eval --bundle z` | `ma offeval z` | `baseline list/get/apply/diff` | `ma basels/show/add/diff` |
| `rule list/disable/enable` | `ma rules/off/on` | `server status/backup` | `ma srv/ma srvbak` |
| `correlate --bundles a,b` | `ma corr a b`（可省，自动选包） | `summary` | `ma sum` |

采集器：`--out/--hospital/--asset/--config/--upload/--services/--password-env/--from-transcript` 分别对应 `-o/-H/位置参数/-f/-u/-s/-e/-t`，长旗标仍可用。

---

## 8. 授权版与许可证

构建分两种：**免费版**（公开分发，默认）与**授权版**（商业交付，构建时注入 licensed 版标记）。`ma version` / `ma -V`（采集器、服务端同样支持 `-V`）输出结构固定：首行「程序名 版本号」（供脚本解析），其后依次为著作权行、项目规划行、商业授权联系行、版本类型行；授权版在许可证验签可用（有效或宽限期）时再加一行「授权给：<被授权方>（有效期至 <日期>）」。中英随语言环境（LANG 等）切换。

- 许可证文件：默认 `/etc/medaudit.license`，环境变量 `MEDAUDIT_LICENSE` 可覆盖；JSON 格式（统一 v2），Ed25519 验签（公钥嵌入二进制，私钥由统一授权台保管）。字段：product（固定 `medaudit`，他产品许可证按签名失败拒绝）、licensee、hosts（授权站点数）、issued、expires、serial，及预留的 activation_id、host_key_fingerprint；签名字段名为 `sig`。签名载荷为紧凑 JSON 规范串：`{"product":…,"licensee":…,"hosts":数字,"issued":…,"expires":…,"serial":…,"activation_id":"","host_key_fingerprint":""}`，键序固定、预留字段恒出现为 `""`、字符串按 Go encoding/json 紧凑编码，取 UTF-8 字节验签。许可证格式的唯一母版为统一授权台 weixun-lic 与 altrootdisk 的 `internal/license` 实现，本产品口径与之逐字对齐。
- 门控范围（中间档）：仅授权版、仅「产生新数据」的操作受门控——服务端一键审计/远程审计、采集器产包（db 预检除外）、`ma audit`；查询、导出、恢复类与只读操作永不拦截。
- 时限口径：剩余 ≤30 天临期提醒（放行）；过期 ≤30 天为宽限期（放行并警告）；超过宽限期拦截，拦截文案给出原因（未找到许可证文件 / 许可证文件格式损坏 / 许可证签名验证失败 / 许可证已过期且超出宽限期）与应放路径。
- 签发：自 2026-10-22 起一律由统一授权台 weixun-lic 签发并记台账（私钥已移交授权台保管）；原 `medaudit-license` 工具已退役（源码留仓备查，不再构建、不再分发）。

## 附录：环境变量速览

| 变量 | 用途 |
|---|---|
| `MEDAUDIT_SERVER` | 服务端地址（次于 `-s`） |
| `MEDAUDIT_USER` / `MEDAUDIT_PASS` | 登录用户/口令（自动登录、ma login 缺省） |
| `MEDAUDIT_PW` | ma audit 目标口令（次于 `-e`，先于交互输入） |
| `MEDAUDIT_HOSPITAL` | 采集器医院缺省 |
| `MEDAUDIT_HPUX_PASSWORD` | 采集器 hpux 子命令口令缺省来源 |
