# 平台备份恢复演练记录

## 2026-10-20 首次演练（M4-3a）

目的：验证平台元数据（MySQL）可备份、可在隔离环境恢复、恢复后应用可正常复算，偿还方案要求的平台自身备份恢复验收。

### 步骤与证据

1. 备份：对 medaudit-platform-mysql（mysql:8.4，127.0.0.1:13306）执行 mysqldump --single-transaction --routines --triggers，产物 /kf/medaudit/backups/medaudit-platform-20261020-1301.sql（452K，含 16 张表 DDL）。
2. 恢复：在新容器 medaudit-restore-mysql（mysql:8.4，127.0.0.1:13309）中先 CREATE DATABASE medaudit（dump 不含建库语句），再导入。
3. 逐表行数校验：源库 16 张表与恢复库逐表 COUNT(*) 全部一致（ALL ROWCOUNTS MATCH）。
4. 应用复算：以恢复库 DSN 在 127.0.0.1:18081 拉起 medaudit-server 副本，GET /api/v1/rules 返回 13 条规则；GET /api/v1/findings?bundle_id=bundle-mysql-20261019-081750 返回 66 条，与生产实例（8080）完全一致。
5. 收尾：演练用 server 副本已停止；恢复容器 medaudit-restore-mysql 保留备查；备份文件保留在 /kf/medaudit/backups/。

### 结论

PASS。备份恢复链路可用；恢复要点：dump 需配合手动建库，应用启动环境变量为 MEDAUDIT_PLATFORM_DSN。

## 2026-10-20 升级路径演练（M4-3c）

用 13:01 的旧版备份（16 表，迁移 004/005 之前）在容器 medaudit-upgrade-test（13310）恢复，
依次应用 migrations/004_evidence.sql、005_api_audits.sql（18 表），用 0.2.0-m4 服务端拉起：
health 正常、17 规则、bundle-mysql 旧数据 findings 66 条与生产一致、/api/v1/api-audits 可查。
结论 PASS：向前兼容迁移可直接在生产库版本链上执行，无数据丢失与接口断裂。
注：上文 migrations/ 指当时的旧 MySQL 迁移目录，旧 MySQL 迁移已于 M37-3.3 删除（现仅 sqlite_migrations/）；演练记录本身按当时原文保留。

## SQLite 平台库备份恢复（M5，2026-10-20）

平台库切换 SQLite 后，备份恢复简化为文件级，演练如下：

1. 备份：对预发库执行 `VACUUM INTO` 生成一致性备份 medaudit-sqlite-drill.db，`integrity_check=ok`（9 个事实包 / 1752 条 findings）。
2. 恢复：以该备份文件为 `MEDAUDIT_PLATFORM_DB` 在 18085 拉起 server 副本：health 正常、9 个事实包可列、新包 findings 8 条、加密证据下载 sha256 与源一致（f75a7e63…）。
3. 结论：PASS。日常备份建议：计划任务定期 VACUUM INTO 到 /kf/medaudit/backups/ 并保留 30 天；恢复即换文件重启，无需建库与导入步骤。
