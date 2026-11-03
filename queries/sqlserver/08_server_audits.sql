-- template: mssql.server_audits
-- version: 1
-- min_privileges: 查看服务器审计需 VIEW SERVER STATE 或 sysadmin
-- description: 服务器审计清单与启用状态。
SELECT name AS audit_name, is_state_enabled AS is_state_enabled
FROM sys.server_audits
ORDER BY name
