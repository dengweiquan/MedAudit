-- template: ora.parameters
-- version: 1
-- min_privileges: SELECT ON V_$PARAMETER（SELECT_CATALOG_ROLE 覆盖）
-- description: 安全相关初始化参数子集（审计开关）。
SELECT NAME AS name, VALUE AS value
FROM v$parameter
WHERE NAME = 'AUDIT_TRAIL'
