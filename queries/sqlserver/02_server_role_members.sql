-- template: mssql.server_role_members
-- version: 1
-- min_privileges: VIEW ANY DEFINITION
-- description: 服务器角色成员关系。固定角色（sysadmin 等）按产品语义在规则侧联合判断。
SELECT r.name AS role_name, m.name AS member_name, m.type_desc AS member_type
FROM sys.server_role_members rm
JOIN sys.server_principals r ON r.principal_id = rm.role_principal_id
JOIN sys.server_principals m ON m.principal_id = rm.member_principal_id
ORDER BY r.name, m.name
