# 传输加密证据采集方案（Oracle 原生网络加密 / MSSQL ForceEncryption）

## 结论先行

- 传输加密证据只能在数据库宿主 OS 侧采集：DB 连接查不到 sqlnet.ora 与 ForceEncryption。
  因此两条规则均为**宿主规则**（os-linux / os-windows），不在 DB 包上评价；
  DB 包上的加密状态仍为 UNKNOWN（无 DB 通道证据），不在报告中伪装成已覆盖。
- 采集器本机客户端配置（采集器所在机的 sqlnet.ora / 注册表）绝不作为远端服务端配置。
- 本方案只评价“是否要求加密”，不鉴定链路实际是否加密（见“明确不评价”）。

## Oracle：sqlnet.ora（Linux 宿主）

- 渠道：Linux 采集器在宿主本机读文件（采集器送到宿主本地执行，非远程 SQL）。
- 实例绑定：`/etc/oratab`（`SID:ORACLE_HOME`）枚举本机 Oracle Home；每 Home 独立出事实
  （Subject=Home 路径，属性含 SID、sqlnet.ora 实际路径、IFILE 链）。
- 文件定位：缺省 `$ORACLE_HOME/network/admin/sqlnet.ora`；TNS_ADMIN 仅当实例级 TNS_ADMIN
  可靠已知时采用——本期不从采集器自身环境变量取 TNS_ADMIN（那是采集器客户端配置，
  不是服务端配置）；从 PMON 进程环境探测实例 TNS_ADMIN 列为后续增强。
- IFILE：递归跟随，深度上限 10，环检测（已访路径不再跟随并记错）；同一参数后出现的值
  覆盖先前值（与 Oracle 参数文件语义一致）。
- 结果语义：
  - `SQLNET.ENCRYPTION_SERVER=required` → 要求原生加密；
  - `requested/accepted/rejected` → 未要求；
  - 入口文件本身确实不存在（ENOENT）→ 取 Oracle 缺省 `accepted`（事实标注 `file_missing=true`，明细中明示）；
  - 入口文件存在但其 IFILE 链内文件缺失/不可读 → 链内解析失败，不猜默认值：
    出 Unsupported 事实并记 partial 收据，规则 UNKNOWN（入口缺失与链内失败严格区分，
    后者不得误入“入口缺失”分支）；
  - 入口文件权限拒绝（EACCES）→ PermissionDenied 事实，规则 UNKNOWN；
    入口 I/O 错误（EIO 等）→ Unsupported 事实并记 partial 收据，规则 UNKNOWN；
    入口错误按类型区分，只有确实不存在才按入口缺失处理；
  - 实例无法确定（无 oratab / 无 Home）→ 盘点事实 `oracle_homes=0`，规则 NA（宿主无 Oracle）。
  - 证据门控收据先行：收据缺失/失败/截断时，安全的 Observed 事实也不判 Ready；
    失败的枚举不得被「无 Oracle Home」盘点事实掩盖为不适用。
- 规则：`os.linux.oracle_native_encryption_not_required`（v1，带证据门控）。

## MSSQL：ForceEncryption（Windows 宿主）

- 渠道：Windows 采集器本机注册表（64 位视图）：
  `HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL` 枚举实例名→实例 ID，
  再读 `<ID>\MSSQLServer\SuperSocketNetLib\ForceEncryption`（DWORD）。
- 实例绑定：每实例独立事实（Subject=实例名，属性含实例 ID 与注册表路径）。
- 结果语义：
  - `ForceEncryption=1` → 已配置强制加密；
  - `=0` 或值缺失（缺省 0）→ 未强制（事实标注 `value_missing=true`，明细中明示）；
  - 值不可读 → PermissionDenied（注册表拒绝访问）或 Unsupported（其他错误）事实，
    并附实例 ID、注册表路径与脱敏错误；该实例不纳入 PASS 结论，但不掩盖真实 FAIL；
  - 多实例汇总：只要任一实例读取/枚举失败且至少一实例可读，收据记 partial——
    评估层继续跑 check：已有明确 `force_encryption=0` 仍判 FAIL，无命中判 UNKNOWN，
    不得因部分实例开启而整体 PASS；全部实例不可读时收据记 denied，规则 UNKNOWN；
  - 宿主无实例 → 盘点事实 `mssql_instances=0`，规则 NA；盘点事实只在枚举
    成功且无跳过时才写——实例名键缺失视同无实例，打开键/读值名失败、
    单个实例 ID 读不到均不写无实例盘点（避免枚举失败误判无实例）。
  - 证据门控收据先行：收据失败时不得被 `mssql_instances=0` 掩盖为不适用；
    收据 partial 时评估层按上条 partial 语义处理。
- 已配置 vs 运行中生效：注册表值只证明“已配置”；重启后生效状态未验证
  （事实 `effective=unknown`，PASS 明细中明示）；注册表 LastWriteTime × 服务进程启动时间
  的生效判定列为后续增强。
- 规则：`os.windows.mssql_force_encryption_off`（v1，带证据门控）。

## 明确不评价（不硬凑）

- 未要求原生加密 ≠ 链路明文：TCPS 等传输层加密不在两条规则评价范围；
  TCPS 部署记入基线豁免，规则描述与明细中明示。
- 当前会话协商结果无可靠 DB 通道可取（go-ora 不暴露协商状态，SQL 也查不到），
  本期不发会话证据；不把“连接成功”说成“已加密”。
- 会话 `encrypt_option` 不替代服务器策略：MSSQL 规则不采会话值。
- Linux 的 `mssql.conf` 渠道本期未实现：框架头明示未检查，不发占位规则。
- 细粒度：Oracle 加密类型（ENCRYPTION_TYPES_SERVER）只记录不判定；
  MSSQL 证书有效性不在本规则范围。

## 权限要求

- Linux：读 `/etc/oratab` + 各 Home 下 `network/admin/sqlnet.ora`（含 IFILE 链上的文件）——
  通常需 root 或 oracle 用户同组权限；不可读 → PermissionDenied，不静默跳过。
- Windows：读 HKLM 注册表（Instance Names + 各实例 SuperSocketNetLib）——
  需本地管理员或等效读权限；不可读 → PermissionDenied。
- 采集失败不降级：收据记失败，规则 UNKNOWN，不判 PASS。

## 事实与规则

- 事实 Source：`linux.oracle_sqlnet` / `win.mssql_force_encryption`；
  Kind 复用 `account_config`（不新增事实种类，FactBundle 合约与 schema 不变）。
- 映射：医疗-06（重要数据与个人健康信息传输采用加密措施）、
  等保 8.1.4.8 a)（采用密码技术保证重要数据在传输过程中的保密性）。
- 覆盖矩阵：见最终验收交付（本方案 + 各步实现汇总）。
