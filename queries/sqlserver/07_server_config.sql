-- template: mssql.server_config
-- version: 1
-- min_privileges: sys.configurations 对 public 可见
-- description: 安全相关服务器配置项（sp_configure 生效值 value_in_use）。
SELECT name AS setting_name,
       CONVERT(nvarchar(64), value_in_use) AS value_in_use,
       CONVERT(nvarchar(64), is_dynamic) AS is_dynamic
FROM sys.configurations
WHERE name IN ('xp_cmdshell', 'clr enabled', 'cross db ownership chaining',
               'Ad Hoc Distributed Queries', 'Ole Automation Procedures',
               'remote admin connections', 'scan for startup procs')
ORDER BY name
