-- template: pg.role_members
-- version: 1
-- min_privileges: pg_auth_members / pg_roles 任意登录角色可读
-- description: 角色成员关系（含 WITH ADMIN OPTION 与授予者）。角色可嵌套，规则侧按路径判定。
SELECT granted.rolname AS role_name,
       member.rolname AS member_name,
       grantor.rolname AS grantor_name,
       m.admin_option::text AS admin_option
FROM pg_auth_members m
JOIN pg_roles granted ON granted.oid = m.roleid
JOIN pg_roles member ON member.oid = m.member
JOIN pg_roles grantor ON grantor.oid = m.grantor
ORDER BY granted.rolname, member.rolname
