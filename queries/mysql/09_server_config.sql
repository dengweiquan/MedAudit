-- template: mysql.server_config
-- version: 3
-- min_privileges: performance_schema.global_variables 读权限
-- description: 安全相关全局变量子集（本地文件导入/通用日志/名称解析/安全传输/口令验证/库名大小写）。
SELECT VARIABLE_NAME AS variable_name, VARIABLE_VALUE AS variable_value
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN ('local_infile', 'general_log', 'skip_name_resolve',
                        'require_secure_transport', 'tls_version', 'bind_address',
                        'secure_file_priv', 'super_read_only', 'lower_case_table_names',
                        'validate_password.policy', 'validate_password.length',
                        'validate_password.mixed_case_count', 'validate_password.number_count',
                        'validate_password.special_char_count')
ORDER BY VARIABLE_NAME
