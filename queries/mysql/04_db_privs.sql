-- template: mysql.db_privs
-- version: 1
-- min_privileges: SELECT ON mysql.db
-- description: 库级权限（作用域 db.*）。
SELECT User AS user, Host AS host, Db AS db,
       Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv,
       Grant_priv, References_priv, Index_priv, Alter_priv,
       Create_tmp_table_priv, Lock_tables_priv,
       Create_view_priv, Show_view_priv, Create_routine_priv, Alter_routine_priv,
       Execute_priv, Event_priv, Trigger_priv
FROM mysql.db
ORDER BY User, Host, Db
