-- template: mssql.db_principals
-- version: 1
-- min_privileges: 目标库的 VIEW DEFINITION（或 db_owner 固定角色）
-- params: DB
-- description: 数据库层主体（数据库用户）。按库分别采集，收据 param_digest 标注库名。
SELECT name AS principal_name, type_desc AS principal_type,
       authentication_type_desc AS authentication_type
FROM {{DB}}.sys.database_principals
WHERE type IN ('S', 'U', 'G', 'R', 'X')
ORDER BY name
