-- template: mysql.accounts
-- version: 1
-- min_privileges: SELECT ON mysql.user
-- description: 账号清单。user@host 为账号稳定全键；只取认证是否存在（布尔），不取口令哈希。
SELECT User AS user, Host AS host,
       plugin AS plugin,
       IF(authentication_string = '', 'N', 'Y') AS has_auth_string,
       account_locked AS account_locked,
       password_expired AS password_expired,
       password_last_changed AS password_last_changed,
       password_lifetime AS password_lifetime
FROM mysql.user
ORDER BY User, Host
