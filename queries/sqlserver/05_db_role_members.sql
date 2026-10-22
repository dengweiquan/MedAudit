-- template: mssql.db_role_members
-- version: 1
-- min_privileges: 目标库的 VIEW DEFINITION
-- params: DB
-- description: 数据库角色成员关系（含 db_owner 等固定数据库角色）。
SELECT r.name AS role_name, m.name AS member_name, m.type_desc AS member_type
FROM {{DB}}.sys.database_role_members rm
JOIN {{DB}}.sys.database_principals r ON r.principal_id = rm.role_principal_id
JOIN {{DB}}.sys.database_principals m ON m.principal_id = rm.member_principal_id
ORDER BY r.name, m.name
