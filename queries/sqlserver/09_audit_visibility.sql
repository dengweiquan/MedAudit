-- template: mssql.audit_visibility
-- version: 1
-- min_privileges: 无（IS_SRVROLEMEMBER 与 HAS_PERMS_BY_NAME 可自查）
-- description: 采集账号对服务器审计目录的元数据可见性自查。仅 sysadmin 或 CONTROL SERVER 视为可见性充分；仅有 VIEW SERVER STATE 等权限时，sys.server_audits 零行不能认定未配置审计（目录视图按可见性过滤）。
SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin, HAS_PERMS_BY_NAME(NULL, NULL, 'CONTROL SERVER') AS has_control
