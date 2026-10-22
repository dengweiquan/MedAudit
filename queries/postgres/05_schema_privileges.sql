-- template: pg.schema_privileges
-- version: 1
-- min_privileges: pg_namespace.nspacl 任意登录角色可读；grantee=0 表示 PUBLIC
-- description: 当前连接库的模式级显式 ACL（仅当前库；跨库需另行连接，见适配器覆盖说明）。
SELECT n.nspname AS schema_name,
       CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE r.rolname END AS grantee_name,
       x.privilege_type AS privilege_type,
       x.is_grantable::text AS is_grantable
FROM pg_namespace n
CROSS JOIN LATERAL aclexplode(n.nspacl) x
LEFT JOIN pg_roles r ON r.oid = x.grantee
WHERE n.nspacl IS NOT NULL
ORDER BY n.nspname, grantee_name, x.privilege_type
