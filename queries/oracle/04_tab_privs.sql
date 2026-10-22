-- template: ora.tab_privs
-- version: 1
-- min_privileges: SELECT ON DBA_TAB_PRIVS
-- description: 指定对象授权。GRANTABLE=Y 保留转授权能力。
SELECT GRANTEE AS grantee, OWNER AS owner, TABLE_NAME AS table_name,
       PRIVILEGE AS privilege, GRANTABLE AS grantable
FROM DBA_TAB_PRIVS
ORDER BY GRANTEE, OWNER, TABLE_NAME, PRIVILEGE
