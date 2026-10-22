-- template: mysql.account_tls
-- version: 1
-- min_privileges: 对 mysql.user 的 SELECT 权限
-- description: 账号传输安全要求（ssl_type / X509）。远程账号未强制 TLS 是补盲规则的数据源。
SELECT user AS user, host AS host, ssl_type AS ssl_type,
       x509_issuer AS x509_issuer, x509_subject AS x509_subject
FROM mysql.user
ORDER BY user, host
