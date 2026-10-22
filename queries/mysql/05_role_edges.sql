-- template: mysql.role_edges
-- version: 1
-- min_privileges: SELECT ON mysql.role_edges
-- description: 角色授予关系边（FROM=角色，TO=被授予者）。激活状态见 default_roles 模板。
SELECT FROM_USER AS from_user, FROM_HOST AS from_host,
       TO_USER AS to_user, TO_HOST AS to_host,
       WITH_ADMIN_OPTION AS with_admin_option
FROM mysql.role_edges
ORDER BY TO_USER, TO_HOST, FROM_USER, FROM_HOST
