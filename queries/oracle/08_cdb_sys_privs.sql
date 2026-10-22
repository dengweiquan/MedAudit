-- template: ora.cdb_sys_privs
-- version: 1
-- min_privileges: SELECT ON CDB_SYS_PRIVS（仅 CDB$ROOT 连接时运行）
-- description: 跨容器系统权限：含 CON_ID 与 COMMON（普通授权跨全部容器生效）。
SELECT GRANTEE AS grantee, PRIVILEGE AS privilege, ADMIN_OPTION AS admin_option,
       COMMON AS common, CON_ID AS con_id
FROM CDB_SYS_PRIVS
ORDER BY CON_ID, GRANTEE, PRIVILEGE
