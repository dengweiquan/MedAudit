-- template: mysql.user_privs
-- version: 1
-- min_privileges: SELECT ON mysql.user
-- description: 全局静态权限（mysql.user 的 *_priv 列）与转授权标志。
SELECT User AS user, Host AS host,
       Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv,
       Reload_priv, Shutdown_priv, Process_priv, File_priv, Grant_priv,
       References_priv, Index_priv, Alter_priv, Show_db_priv, Super_priv,
       Create_tmp_table_priv, Lock_tables_priv, Execute_priv,
       Repl_slave_priv, Repl_client_priv,
       Create_view_priv, Show_view_priv, Create_routine_priv, Alter_routine_priv,
       Create_user_priv, Event_priv, Trigger_priv, Create_tablespace_priv,
       Create_role_priv, Drop_role_priv
FROM mysql.user
ORDER BY User, Host
