-- template: mysql.server_config
-- version: 1
-- min_privileges: performance_schema.global_variables 读权限
-- description: 安全相关全局变量子集（本地文件导入/通用日志/名称解析/安全传输）。
SELECT VARIABLE_NAME AS variable_name, VARIABLE_VALUE AS variable_value
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN ('local_infile', 'general_log', 'skip_name_resolve',
                        'require_secure_transport', 'tls_version', 'bind_address',
                        'secure_file_priv', 'super_read_only')
ORDER BY VARIABLE_NAME
