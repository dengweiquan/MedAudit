-- template: pg.settings
-- version: 2
-- min_privileges: pg_settings 任意登录角色可读
-- description: 安全相关服务器参数子集（监听/SSL/口令加密/审计日志/系统表修改）。
SELECT name, setting, COALESCE(unit, '') AS unit
FROM pg_settings
WHERE name IN ('listen_addresses', 'port', 'ssl', 'password_encryption',
               'log_connections', 'logging_collector', 'log_statement', 'log_disconnections',
               'allow_system_table_mods', 'shared_preload_libraries')
ORDER BY name
