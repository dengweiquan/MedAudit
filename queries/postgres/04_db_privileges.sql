-- template: pg.db_privileges
-- version: 1
-- min_privileges: pg_database.datacl 任意登录角色可读；grantee=0 表示 PUBLIC
-- description: 数据库级显式 ACL（aclexplode 展开）。注意：datacl 为 NULL 的数据库只有默认权限，不产生行。
SELECT d.datname AS database_name,
       CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE r.rolname END AS grantee_name,
       x.privilege_type AS privilege_type,
       x.is_grantable::text AS is_grantable
FROM pg_database d
CROSS JOIN LATERAL aclexplode(d.datacl) x
LEFT JOIN pg_roles r ON r.oid = x.grantee
ORDER BY d.datname, grantee_name, x.privilege_type
