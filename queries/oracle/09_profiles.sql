-- template: ora.profiles
-- version: 1
-- min_privileges: SELECT ON DBA_PROFILES（无权时回执如实记 permission_denied）
-- description: 口令与资源概要文件（PASSWORD 类）：口令寿命/失败锁定/复用限制。
SELECT PROFILE AS profile, RESOURCE_NAME AS resource_name,
       COALESCE(LIMIT, '') AS limit_value
FROM DBA_PROFILES
WHERE RESOURCE_TYPE = 'PASSWORD'
ORDER BY PROFILE, RESOURCE_NAME
