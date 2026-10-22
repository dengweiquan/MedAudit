-- 009_auth_users_ext.sql — M20 用户管理：禁用标志 + 强制改密标志。
-- 存量 admin 置 must_change_pwd=1：升级后首次登录须改口令（与试点清单勾稽）。
ALTER TABLE auth_users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE auth_users ADD COLUMN must_change_pwd INTEGER NOT NULL DEFAULT 0;
UPDATE auth_users SET must_change_pwd = 1 WHERE username = 'admin';
