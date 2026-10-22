-- template: mysql.global_grants
-- version: 1
-- min_privileges: SELECT ON mysql.global_grants
-- description: 全局动态权限（8.0+）。WITH_GRANT_OPTION 保留转授权标志。
SELECT User AS user, Host AS host, Priv AS privilege, With_grant_option AS with_grant_option
FROM mysql.global_grants
ORDER BY User, Host, Priv
