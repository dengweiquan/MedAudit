-- template: ora.users
-- version: 1
-- min_privileges: SELECT ON DBA_USERS
-- description: 用户清单（状态、认证类型、profile）。不读取口令哈希；当前策略不能证明实际密码强度。
SELECT USERNAME AS username, ACCOUNT_STATUS AS account_status,
       AUTHENTICATION_TYPE AS authentication_type, PROFILE AS profile,
       CREATED AS created
FROM DBA_USERS
ORDER BY USERNAME
