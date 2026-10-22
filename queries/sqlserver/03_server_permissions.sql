-- template: mssql.server_permissions
-- version: 1
-- min_privileges: VIEW ANY DEFINITION
-- description: 服务器层显式权限。state_desc 保留 GRANT/DENY/GRANT_WITH_GRANT_OPTION 语义；
-- 固定服务器角色的权限不在此视图内，须与 server_role_members 联合判断。
SELECT pr.name AS grantee_name, pr.type_desc AS grantee_type,
       pe.permission_name AS permission_name, pe.state_desc AS state_desc,
       pe.class_desc AS class_desc
FROM sys.server_permissions pe
JOIN sys.server_principals pr ON pr.principal_id = pe.grantee_principal_id
ORDER BY pr.name, pe.permission_name
