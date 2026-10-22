-- template: mssql.databases
-- version: 1
-- min_privileges: VIEW ANY DEFINITION
-- description: 联机用户数据库清单（基础设施模板，用于按库采集；不直接产生权限事实）。
SELECT name AS database_name FROM sys.databases
WHERE database_id > 4 AND state_desc = 'ONLINE'
ORDER BY name
