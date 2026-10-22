-- template: pg.object_privileges
-- version: 1
-- min_privileges: pg_class.relacl 任意登录角色可读；grantee=0 表示 PUBLIC
-- description: 当前连接库的对象级显式 ACL（表/分区表/视图/物化视图/外表/序列，排除系统模式）。仅当前库。
SELECT n.nspname AS schema_name,
       c.relname AS object_name,
       c.relkind::text AS object_kind,
       CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE r.rolname END AS grantee_name,
       x.privilege_type AS privilege_type,
       x.is_grantable::text AS is_grantable
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL aclexplode(c.relacl) x
LEFT JOIN pg_roles r ON r.oid = x.grantee
WHERE c.relacl IS NOT NULL
  AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY n.nspname, c.relname, grantee_name, x.privilege_type
