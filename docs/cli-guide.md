# MedAudit 工程师 CLI 手册（ma 命令族）

**适用版本 0.25.0-m23**。Web 工作台面向客户（点审计、看问题、导出报告）；工程师的执行面是本文的 `ma` 命令族——按 HP-UX LVM 风格设计：**命令名 = `ma` + 对象 + 动作**（如 `pvcreate` 之于 `maassetadd`），一命令一件事；目标（ID/端点）一律**位置参数**；选项只用**单字母短旗标**；当前医院等上下文存会话，不逐条命令重复声明。

老 `medauditctl` 命令族自 0.25.0 起**移除**（对照表见第 7 节）。

---

## 0. 快速开始（5 分钟）

```bash
# 安装：把安装包 bin/ 加入 PATH（内含 ma 本体、ma.exe 与 39 个 ma* 链接）
ma -s http://<服务器>:8080 login admin     # 口令交互输入（不回显）；或环境变量 MEDAUDIT_PASS
mawhoami                                   # admin @ http://<服务器>:8080 + 当前医院
maassetadd db-mysql 10.0.0.12:3306/his -u root -n '门诊 MySQL' -i db-mysql-01
maaudit db-mysql-01                        # 口令交互输入；或 -e 环境变量名 / 环境 MEDAUDIT_PW
mafind <事实包ID> -c FAIL                  # 看问题（审计输出里有包 ID）
mareport <事实包ID>                        # 生成报告并下载 Word（自动命名 report-<包ID>.docx）
```

两种调用形式等价：链接名直接执行（`maaudit x`），或经分发器 `ma audit x` / `ma maaudit x`。只敲 `ma` 打印全族索引。

---

## 1. 通用约定

### 1.1 服务端地址解析

优先级：全局 `-s <url>`（写在命令前，如 `ma -s http://srv:8080 login admin`）> 环境变量 `MEDAUDIT_SERVER` > 会话文件 > `http://127.0.0.1:8080`。

### 1.2 会话与上下文

- `malogin` 成功后会话存 `~/.medaudit/session.json`（0600）：服务地址、用户名、会话 Cookie、**当前医院**。**不存口令**。
- 当前医院（上下文）：`-h` 旗标 > `mause <医院ID>` 设定值 > 本站医院（单院部署自动取本站，通常无需关心）。多院/实验室实例先 `mause` 一次，后续命令（基线列表、汇总、关联自动选包等）都按此上下文工作。
- 无会话文件但环境变量 `MEDAUDIT_USER`/`MEDAUDIT_PASS` 齐备时自动登录（脚本场景）；注意本机留有过期会话文件会挡住自动登录，先 `malogin` 刷新一次。
- 服务端重启后会话失效（内存会话），重新 `malogin` 即可。

### 1.3 口令纪律

任何口令不落盘、不进平台库、不进命令行明文：

| 场景 | 来源顺序 |
|---|---|
| 平台登录 | 环境 `MEDAUDIT_PASS` > 交互输入 |
| 审计目标（maaudit/mauseradd/mauserpw） | `-e <环境变量名>` > 环境 `MEDAUDIT_PW`（仅审计） > 交互输入 |
| 批量清单/采集器 | 文件中只写环境变量名，运行时取环境 |

### 1.4 短旗标总表（全族统一）

| 旗标 | 含义 | 旗标 | 含义 |
|---|---|---|---|
| `-s` | 服务端地址（全局，置于命令前） | `-o` | 输出文件 |
| `-u` | 账号 | `-f` | 输入文件（清单/labels/基线） |
| `-n` | 名称 | `-j` | JSON 输出 |
| `-i` | 资产 ID（登记时指定） | `-c` | 结论过滤（mafind） |
| `-h` | 医院覆盖 | `-r` | 规则过滤 |
| `-b` | 基线 ID / 基线文件 | `-k` | 类型过滤（maassetls） |
| `-e` | 口令来源环境变量名 | `-a` | 资产过滤（mabundlels） |
| `-U` | 回连地址 server_url（WinRM 资产） | `-d` | 中间件目录（远程资产 labels 的 mw_home） |
| `-F` | 有 FAIL 时退出码 2（脚本门禁） | `-y` | 免确认（mabaseexempt） |

短旗标与位置参数可交错书写（`mafind <包> -c FAIL` 与 `mafind -c FAIL <包>` 等价）。`-h` 在本族中是「医院」，不是 help；看帮助敲 `ma`。

### 1.5 退出码

0 正常；1 执行错误；2 业务 FAIL（仅 `-F` 给出时）。

---

## 2. 命令族全表

### 2.1 会话与上下文

| 命令 | 说明 |
|---|---|
| `malogin [user]` | 登录（缺省 admin 或环境 `MEDAUDIT_USER`） |
| `malogout` | 注销并清除本地会话 |
| `mawhoami` | 当前用户、服务端、当前医院及其来源 |
| `mause [hospital]` | 无参 = 查看上下文；有参 = 设定当前医院 |
| `masite` | 本站医院信息（未初始化时提示多院模式） |

### 2.2 平台账号

| 命令 | 说明 |
|---|---|
| `mauserls` | 用户列表（状态、强制改密、创建时间） |
| `mauseradd <name> [-e VAR]` | 建号；新账号首登强制改密 |
| `mauserpw <name> [-e VAR]` | 重置口令（吊销其全部会话、首登强制改密） |
| `mauseroff <name>` / `mauseron <name>` | 禁用（吊销会话）/ 启用；防自锁（不能禁用自己与最后一个可用账号） |

### 2.3 审计对象（资产）

| 命令 | 说明 |
|---|---|
| `maassetls [-k 类型] [-j]` | 资产列表 |
| `maassetadd <类型> <端点> [-i id] [-n 名称] [-u 账号] [-h 医院] [-f labels文件] [-U 回连地址] [-d 远程目录] [-s 服务清单]` | 登记资产；端点语法见第 3 节；`-i` 缺省由类型+主机推导 |
| `maassetshow <id>` | 资产详情（含 labels 参数全量） |
| `maassetmod <id> [端点] [-n 名称] [-u 账号] [-f labels文件] [-U 回连地址] [-d 目录] [-s 服务清单]` | 修改：给端点则按新端点重建参数；只给旗标则字段级覆盖 |
| `maassetrm <id>` | 删除登记（历史事实包/报告保留） |

### 2.4 审计执行与评估

| 命令 | 说明 |
|---|---|
| `maaudit <资产id> [-b 基线] [-e VAR] [-F]` | 一键审计：db 类走数据库通道，os/mw 类走远程推送（按资产类型自动分发） |
| `maaudit -f 清单.yaml [-F]` | 批量巡检（清单格式同旧版：asset/type/password_env/baseline） |
| `maeval <包id> [-b 基线] [-F]` | 对已导入的包在线评估（每次评估追加一轮） |
| `maoffeval <包.zip> [-b 基线.json] [-o 报告.docx] [-j] [-F]` | 离线评估：本地同一规则引擎求值，可出离线 Word；**不应用本站规则启停**（纯技术口径） |

### 2.5 事实包

| 命令 | 说明 |
|---|---|
| `mabundlels [-a 资产] [-j]` | 事实包列表 |
| `mabundlein <文件.zip>` | 导入离线事实包（机器通道，免登录亦可） |
| `mabundleshow <包id> [-j]` | 元数据、逐模板收据（含截断标注）、事实构成 |
| `mabundledrift <新包> <旧包>` | 两包事实层漂移（须同资产同适配器） |
| `mabundleeff <包id> [-j]` | 有效权限（传递闭包，派生权限带见证路径） |

### 2.6 问题与报告

| 命令 | 说明 |
|---|---|
| `mafind <包id> [-c 结论] [-r 规则] [-j] [-o 清单.csv]` | 问题清单；`-j` 含 finding 数字 id（豁免用）；CSV 为 UTC 原始时间 |
| `mareport <包id> [-o 报告.docx]` | 生成报告并下载 Word（-o 缺省自动命名） |
| `mareportls` | 报告列表 |
| `mareportshow <报告id> [-j]` | 报告快照摘要（问题数、脚本覆盖、章节） |
| `mareportfix <报告id> [-r 规则]` | 打印修复脚本四件套（前置检查→修复→验证→回滚；平台只生成不执行） |

### 2.7 基线与规则

| 命令 | 说明 |
|---|---|
| `mabasels [-h 医院] [-j]` | 当前医院的基线列表 |
| `mabaseshow <id> [-o 文件]` | 查看/导出基线（文件即全量格式，可再 `mabaseadd` 回登） |
| `mabaseadd -f 基线.json` | 登记基线（文件缺 hospital_id 时取上下文） |
| `mabasediff <基线A> <基线B>` | 放行集差异（参数可为基线 ID 或 .json 文件） |
| `mabaseexempt <finding-id> [-b 基线] [-y] [原因…]` | 一键豁免：按问题证据推导放行项 → 预览 → 确认 → 加入基线。`-b` 指定基线（存在则追加、不存在则新建）；缺省时唯一同目标基线自动选、无则新建 `bl-exempt-<目标>`。不支持豁免的规则会明确提示（改用 maruleoff 整类关闭） |
| `marulels [-j]` | 规则清单与本站启停状态（含关闭原因留痕） |
| `maruleoff <规则id> <原因…>` | 关闭检查项（本站作用域，原因必填并留痕；关闭项不计结果、不进报告） |
| `maruleon <规则id>` | 恢复检查项 |

基线与规则启停的分工：基线 = 对**具体主体**的已知例外（厂商/内置账号）；规则启停 = 对**整条检查项**的本站停用。基线只在评估时选用才生效（`maaudit -b` / `maeval -b`）。

### 2.8 关联、汇总、服务端

| 命令 | 说明 |
|---|---|
| `macorr [包id…]` | 跨包提权路径分析；无参时自动取当前医院各资产最新包（2–12 个） |
| `masum` | 医院风险汇总（有上下文时只显示当前医院） |
| `masrv` | 服务端状态（健康、版本、当前会话用户） |
| `masrvbak <备份文件>` | 平台库在线备份（VACUUM INTO 一致性快照，0600 落盘并打印 sha256）。恢复 = 停服 → 以快照替换平台库文件 → 启服。**切勿直接 cp 运行中的库主文件**（WAL 模式会丢未合并事务） |

---

## 3. 资产端点语法（maassetadd 第二个参数）

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
malogin
maaudit -f inventory.yaml -F     # 清单逐项给 asset/type/password_env/baseline；任一 FAIL 退出码 2
```

### 5.2 现场单机审计 + 出报告

```bash
maassetadd db-oracle 10.0.0.11:1521/HISDB -u reader -n 核心库 -i db-ora-01
maaudit db-ora-01 -e ORA_PW
mafind <包ID> -c FAIL
mabaseexempt <finding-id> -y 厂商维护账号    # 个别例外一键入基线
maeval <包ID> -b <基线ID>
mareport <包ID>
```

### 5.3 隔离现场（无内网）

```bash
medaudit-collector db -f db.yml -o bundle.zip        # 目标侧采集
maoffeval bundle.zip -o 离线报告.docx                # 本地评估出 Word（不应用规则启停）
# 回到联网环境后： mabundlein bundle.zip && maeval <包ID>  （在线口径为准）
```

### 5.4 整改复核（闭环）

整改后对同一资产再 `maaudit`，用 `mabundledrift <新包> <旧包>` 看事实层变化；销账口径以 Web「复检对比」为准。

### 5.5 例外对齐（新到一家现场）

先原始口径审计 → 对厂商/内置账号类问题逐条 `mabaseexempt`（或 Web 问题页一键加入）→ `maeval -b <基线>` 复评 → 剩余 FAIL 即真实待整改项。

---

## 6. 常见错误与处理

| 现象 | 处理 |
|---|---|
| 未登录或会话已过期 | 服务端重启/会话过期 → `malogin`；注意过期会话文件会挡环境变量自动登录 |
| 未设定当前医院 | 多院实例先 `mause <医院ID>`；单院部署自动取本站不会出现 |
| 环境变量 X 未设置 | `-e` 指定的变量名在本机环境不存在；export 后重试（口令不要写进命令明文） |
| bundle 已导入（同秒碰撞） | 包 ID 为秒级分辨率；maaudit 已自动等 2 秒重试一次，导入场景手动间隔 2 秒 |
| 漂移对比报「只能对比同一资产」 | 换同资产的两个包 |
| mabasediff 提示基线不存在 | 上下文医院不对：`-h` 指定或先 `mause`；跨院基线先 `mabaseshow -o` 导出文件再按文件比 |

---

## 7. 旧命令对照（medauditctl → ma，0.25.0 起旧命令移除）

| 旧 | 新 | 旧 | 新 |
|---|---|---|---|
| `login/logout/whoami` | `malogin/malogout/mawhoami` | `bundle list/import/show/drift/effective` | `mabundlels/in/show/drift/eff` |
| `user create/list/reset-password/disable/enable` | `mauseradd/ls/pw/off/on` | `findings --bundle B` | `mafind B` |
| `audit db/remote --asset A` | `maaudit A`（自动分发） | `report --bundle B --docx f` | `mareport B -o f` |
| `audit batch --inventory f` | `maaudit -f f` | `report list/show/scripts` | `mareportls/show/fix` |
| `evaluate --bundle B` | `maeval B` | `asset create/update/delete` | `maassetadd/mod/rm` |
| `eval --bundle z` | `maoffeval z` | `baseline list/get/apply/diff` | `mabasels/show/add/diff` |
| `rule list/disable/enable` | `marulels/off/on` | `server status/backup` | `masrv/masrvbak` |
| `correlate --bundles a,b` | `macorr a b`（可省，自动选包） | `summary` | `masum` |

采集器：`--out/--hospital/--asset/--config/--upload/--services/--password-env/--from-transcript` 分别对应 `-o/-H/位置参数/-f/-u/-s/-e/-t`，长旗标仍可用。

---

## 附录：环境变量速览

| 变量 | 用途 |
|---|---|
| `MEDAUDIT_SERVER` | 服务端地址（次于 `-s`） |
| `MEDAUDIT_USER` / `MEDAUDIT_PASS` | 登录用户/口令（自动登录、malogin 缺省） |
| `MEDAUDIT_PW` | maaudit 目标口令（次于 `-e`，先于交互输入） |
| `MEDAUDIT_HOSPITAL` | 采集器医院缺省 |
| `MEDAUDIT_HPUX_PASSWORD` | 采集器 hpux 子命令口令缺省来源 |
