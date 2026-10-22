-- template: mysql.global_vars
-- version: 1
-- min_privileges: 无（全局变量读权限）
-- description: 强制角色、角色自动激活与 partial revokes 开关。
SELECT @@GLOBAL.mandatory_roles AS mandatory_roles,
       @@GLOBAL.activate_all_roles_on_login AS activate_all_roles_on_login,
       @@GLOBAL.partial_revokes AS partial_revokes
