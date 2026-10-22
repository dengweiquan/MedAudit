-- template: ora.pwfile_users
-- version: 1
-- min_privileges: SELECT ON V_$PWFILE_USERS
-- description: 口令文件管理授权（SYSDBA/SYSOPER 等）。DBA 角色不等于 SYSDBA；口令文件不是全部管理认证路径。
SELECT USERNAME AS username, SYSDBA AS sysdba, SYSOPER AS sysoper,
       SYSASM AS sysasm, SYSBACKUP AS sysbackup, SYSDG AS sysdg, SYSKM AS syskm
FROM V$PWFILE_USERS
ORDER BY USERNAME
