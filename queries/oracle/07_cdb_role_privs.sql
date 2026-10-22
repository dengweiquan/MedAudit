-- template: ora.cdb_role_privs
-- version: 1
-- min_privileges: SELECT ON CDB_ROLE_PRIVS（仅 CDB$ROOT 连接时运行）
-- description: 跨容器角色授予边：PDB 内的 DBA 授予从根容器视角同样可见。本模板边不进入单容器传递闭包。
SELECT GRANTEE AS grantee, GRANTED_ROLE AS granted_role,
       ADMIN_OPTION AS admin_option, DEFAULT_ROLE AS default_role,
       COMMON AS common, CON_ID AS con_id
FROM CDB_ROLE_PRIVS
ORDER BY CON_ID, GRANTEE, GRANTED_ROLE
