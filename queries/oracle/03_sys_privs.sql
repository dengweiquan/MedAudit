-- template: ora.sys_privs
-- version: 1
-- min_privileges: SELECT ON DBA_SYS_PRIVS
-- description: 系统权限（含 ANY 类与转授权）。按容器作用域解释，不把"有角色"等同于权限有效。
SELECT GRANTEE AS grantee, PRIVILEGE AS privilege, ADMIN_OPTION AS admin_option
FROM DBA_SYS_PRIVS
ORDER BY GRANTEE, PRIVILEGE
