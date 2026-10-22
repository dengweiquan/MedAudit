-- template: pg.hba
-- version: 1
-- min_privileges: pg_hba_file_rules 视图（通常需 SUPERUSER；无权时回执如实记 permission_denied）
-- description: 客户端认证规则（pg_hba.conf 生效内容）：连接类型/库/用户/地址/认证方法。口令文件本体不读。
SELECT line_number::text AS line_number,
       type AS conn_type,
       array_to_string(database, ',') AS databases,
       array_to_string(user_name, ',') AS user_names,
       COALESCE(address, '') AS address,
       COALESCE(netmask, '') AS netmask,
       auth_method,
       COALESCE(array_to_string(options, ' '), '') AS options,
       COALESCE(error, '') AS parse_error
FROM pg_hba_file_rules
ORDER BY line_number
