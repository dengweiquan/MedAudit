-- 007_auth_users.sql — M12 登录鉴权：工作台登录用户（口令仅存 bcrypt 哈希）
-- 注：001 已有一张 users 表（原始设计的署名用户，含外键引用），故另名 auth_users。
CREATE TABLE IF NOT EXISTS auth_users (
  username      TEXT NOT NULL PRIMARY KEY,
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
