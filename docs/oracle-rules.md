# Oracle 规则补齐（M13，服务端 0.13.0-m13 起，规则总数 59）

新增 4 条（全部基于既有事实 ora.tab_privs / ora.users，不新增采集）：
- db.oracle.public_object_grant（high）：PUBLIC 对象授权。业务模式对象全判；
  厂商维护模式仅敏感字典对象（USER$/DBA_USERS/DBA_TAB_PRIVS 等）判。
- db.oracle.sys_schema_grant（high）：SYS/SYSTEM 对象被真实业务用户持有
  （以用户清单区分用户/角色；厂商维护账号与目录角色不判）。
- db.oracle.grant_option_spread（medium）：业务侧 GRANT OPTION 转授能力。
- db.oracle.default_account_open（medium）：厂商默认/示例账号 OPEN。

噪声校准（存量实测，同一生产 Oracle 包）：朴素口径会产生 3678 条厂商内部
互授噪声（MDSYS 对 PUBLIC 发布 2605 条等）；以 cdb_users 的 oracle_maintained
标记 + 内置厂商清单 + 用户/角色区分校准后，存量命中 0/0/0/0。
对象名含点（MDSYS 的 Java 资源）要求 Scope 按第一个点切分所有者。

验证（kf03 ARKPDB1）：植入 HISAPP.PAT_RECORDS 授 PUBLIC、MEDAUDIT_PROTO 带
GRANT OPTION、DBSNMP 解锁，四条各命中 1；SYS 授予命中存量 45 条（arkvault
应用账号与采集账号的真实授予——采集账号 medaudit_proto 持有 SYS 字典视图
直查权属原型期授权，属真命中，处置路径为基线豁免：已实证基线使 45→44 且
目标行精确消失）。收紧（回收两授权 + 重新锁定 DBSNMP）后复采：三条归零。
植入已按惯例恢复保留在测试 PDB 供查看（hisapp/M13His!2026、dbsnmp 口令
M13Test!2026，均测试专用；HISAPP 为普通业务模式名，排序在厂商模式之前，
保证其授权落在 tab_privs 采集窗口内）。

已知边界：tab_privs 采集上限 5000 行（该 PDB 实测 51658 行，按 GRANTEE,
OWNER 排序截取）——对象类规则的覆盖范围即采集窗口，事实包对此诚实标记
PARTIAL。窗口外授权不在判定范围，后续可按被授者分片采集解决。
