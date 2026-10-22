-- template: pg.role_settings
-- version: 1
-- min_privileges: pg_db_role_setting 任意登录角色可读
-- description: 角色/库级参数设置（ALTER ROLE/DATABASE SET），如被改写的 search_path。
SELECT COALESCE(r.rolname, 'ALL') AS role_name,
       COALESCE(d.datname, 'ALL') AS database_name,
       s.setconfig::text AS settings
FROM pg_db_role_setting s
LEFT JOIN pg_roles r ON r.oid = s.setrole
LEFT JOIN pg_database d ON d.oid = s.setdatabase
ORDER BY role_name, database_name
