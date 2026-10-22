-- template: pg.databases
-- version: 1
-- min_privileges: pg_database 任意登录角色可读
-- description: 集群内数据库清单（所有者/编码/是否允许连接）。
SELECT d.datname AS database_name,
       r.rolname AS owner_name,
       pg_encoding_to_char(d.encoding) AS encoding,
       d.datallowconn::text AS allow_conn,
       d.datistemplate::text AS is_template
FROM pg_database d
JOIN pg_roles r ON r.oid = d.datdba
ORDER BY d.datname
