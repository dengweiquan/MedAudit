-- template: mssql.db_permissions
-- version: 1
-- min_privileges: 目标库的 VIEW DEFINITION
-- params: DB
-- description: 数据库层显式权限。DENY 语义保留，不简化。
SELECT pr.name AS grantee_name, pr.type_desc AS grantee_type,
       pe.permission_name AS permission_name, pe.state_desc AS state_desc,
       pe.class_desc AS class_desc
FROM {{DB}}.sys.database_permissions pe
JOIN {{DB}}.sys.database_principals pr ON pr.principal_id = pe.grantee_principal_id
ORDER BY pr.name, pe.permission_name
