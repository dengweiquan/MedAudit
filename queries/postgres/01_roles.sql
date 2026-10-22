-- template: pg.roles
-- version: 1
-- min_privileges: pg_roles 视图任意登录角色可读（该视图不含口令列）
-- description: 集群角色与关键属性：SUPERUSER / CREATEROLE / CREATEDB / LOGIN / INHERIT / REPLICATION / BYPASSRLS。
SELECT rolname AS role_name,
       rolsuper::text AS is_superuser,
       rolinherit::text AS inherit,
       rolcreaterole::text AS can_create_role,
       rolcreatedb::text AS can_create_db,
       rolcanlogin::text AS can_login,
       rolreplication::text AS replication,
       rolbypassrls::text AS bypass_rls,
       COALESCE(rolvaliduntil::text, '') AS valid_until,
       rolconnlimit::text AS conn_limit
FROM pg_roles
ORDER BY rolname
