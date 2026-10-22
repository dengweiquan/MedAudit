-- template: ora.role_privs
-- version: 1
-- min_privileges: SELECT ON DBA_ROLE_PRIVS
-- description: 角色授予边。DEFAULT_ROLE=NO 为条件激活（需 SET ROLE）；嵌套角色由采集器展开，路径保留。
SELECT GRANTEE AS grantee, GRANTED_ROLE AS granted_role,
       ADMIN_OPTION AS admin_option, DELEGATE_OPTION AS delegate_option,
       DEFAULT_ROLE AS default_role
FROM DBA_ROLE_PRIVS
ORDER BY GRANTEE, GRANTED_ROLE
