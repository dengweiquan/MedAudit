-- template: ora.cdb_users
-- version: 1
-- min_privileges: SELECT ON CDB_USERS（仅 CDB$ROOT 连接时运行）
-- description: 跨容器用户清单：含 CON_ID 与 COMMON 标记，识别只在某个 PDB 存在的本地账号。
SELECT USERNAME AS username, ACCOUNT_STATUS AS account_status,
       COMMON AS common, ORACLE_MAINTAINED AS oracle_maintained,
       CON_ID AS con_id
FROM CDB_USERS
ORDER BY CON_ID, USERNAME
