-- template: mysql.default_roles
-- version: 1
-- min_privileges: SELECT ON mysql.default_roles; 允许读全局变量 mandatory_roles / activate_all_roles_on_login
-- description: 默认角色与强制角色配置。当前会话激活角色只证明采集连接，不证明应用账号。
SELECT DEFAULT_ROLE_USER AS role_user, DEFAULT_ROLE_HOST AS role_host,
       USER AS user, HOST AS host
FROM mysql.default_roles
ORDER BY USER, HOST, DEFAULT_ROLE_USER, DEFAULT_ROLE_HOST
