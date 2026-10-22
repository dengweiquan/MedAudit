-- template: pg.instance
-- version: 1
-- min_privileges: 无（会话级函数，任意登录角色可查）
-- description: 实例版本与本次连接身份（采集者身份与被核查主体分开记录）。
SELECT current_setting('server_version') AS server_version,
       current_user AS current_user_name,
       session_user AS session_user_name,
       current_database() AS database_name,
       current_setting('port') AS server_port
