# M5：平台元数据库 MySQL → SQLite 切换记录（2026-10-20）

## 决策

- 背景：方案 V1.1 约定平台元数据存独立 MySQL。实际部署为单机中心服务，独立数据库容器带来安装、运维与备份的额外负担。
- 决策（2026-10-20，用户批准）：平台**元数据库**改用嵌入式 SQLite 单文件部署，追求轻便。**此为对方案 V1.1 的有意偏离**，在此备案；后续若方案升版应同步修订该条。
- 不受影响：MySQL 作为**被核查目标**的采集适配器、规则与支持状态完全不变。

## 技术方案

- 驱动：modernc.org/sqlite（纯 Go、无 CGO），服务端二进制单文件部署。
- 接入：`internal/platform/db.go` 的 `Open(path)`；环境变量 `MEDAUDIT_PLATFORM_DB` 指定数据文件路径（替代原 `MEDAUDIT_PLATFORM_DSN`）。
- 并发：WAL 模式 + `busy_timeout=5000` + 单连接串行化写入（平台负载为批量导入/评估，单写者足够）。
- 迁移执行器：`internal/platform/migrate.go` 内嵌 `sqlite_migrations/`（与 MySQL 版 001–005 一一对应的 SQLite 方言翻译），服务端启动时按版本幂等应用，版本记录沿用 `schema_migrations` 表。
- 方言修正共 4 处：`JSON_LENGTH` → `json_array_length`（import.go ×2），`DATE_FORMAT` → `strftime`（import.go / evaluate.go / api_audit_handlers.go 各 1）。
- 时间语义：原 MySQL 容器为 UTC，SQLite `CURRENT_TIMESTAMP` 同为 UTC，历史与新数据口径一致。

## 数据迁移（ETL）

- 工具：`cmd/medaudit-etl`（仓库内，一次性用途）：源 MySQL 全量逐表复制到新建 SQLite 库，BLOB 列字节直传、其余文本化，时间按 UTC 文本对齐。
- 结果：17 张数据表共 1779 行，逐表行数与源库一致；`integrity_check=ok`、`foreign_key_check=ok`。
- 目标文件：`/kf/medaudit/data/medaudit.db`（5.6MB）。

## 回归验证（预发副本库 + 生产）

- 读路径：health=0.3.0-sqlite；8 个事实包的 facts/收据计数与迁移前金标准逐一一致（8509/7333/350/14/67/332/1086/362）；规则 21 条；API 越权报告存档可查；PG 包 findings 8 条。注：事实包列表查询在原 MySQL 上已因 sort memory 不足报错（Error 1038），SQLite 下正常——该存量问题随迁移消除。
- 写路径（预发新采集全流程）：PG 重新采集 67 facts → 导入 201 → 重复导入 duplicate → 证据下载 sha256 与原始 zip 逐字节一致 → 评估 8 findings → 复核落库（review_status=confirmed）→ 报告生成（含 coverage）→ Word 导出为合法 docx。
- 备份恢复：`VACUUM INTO` 备份（integrity ok，9 包/1752 findings）→ 以备份文件拉起服务副本，列表/证据解密（sha256 与源一致 f75a7e63…）全部正常。日常备份即文件级，见运维手册第 6 节。
- 生产切换：2026-10-20 15:47 完成，8080 已运行 0.3.0-sqlite + SQLite 平台库，全量复核通过。

## 回退路径

- MySQL 平台容器 `medaudit-platform-mysql` 与数据**未做任何改动**，保持原状。
- 旧二进制 `/tmp/medaudit-server-mysql.bak`、旧启动脚本 `/tmp/start-medaudit-server-mysql.sh.bak` 保留；回退 = 换回二进制与脚本重启（注意：切换后 SQLite 侧新增数据不会自动回流 MySQL，回退前需评估）。

## 已知边界

- SQLite 单写者：当前单实例部署无影响；若未来需多台管理服务共享同一平台库，需迁回独立数据库服务。
- 数据文件与 WAL 同目录（`medaudit.db` / `-wal` / `-shm`），备份请用 `VACUUM INTO` 或停写后整体复制，避免只拷主文件漏掉未 checkpoint 的 WAL 内容。
