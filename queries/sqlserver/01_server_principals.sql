-- template: mssql.server_principals
-- version: 1
-- min_privileges: VIEW ANY DEFINITION（或对 sys.server_principals 的 SELECT 权限）
-- description: 服务器层主体（登录）。采集连接身份不当作应用连接身份。
SELECT name AS principal_name, type_desc AS principal_type,
       is_disabled AS is_disabled, default_database_name AS default_database_name
FROM sys.server_principals
WHERE type IN ('S', 'U', 'G', 'R')
ORDER BY name
