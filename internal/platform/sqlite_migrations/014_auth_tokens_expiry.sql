-- 014 超级令牌有效期（M37-3.2）：expires_at 为 UTC 文本（与 created_at 同格式）。
-- 老令牌迁移时视为「生成时间 + 90 天」（与缺省有效期一致）。
ALTER TABLE auth_tokens ADD COLUMN expires_at TEXT;
UPDATE auth_tokens SET expires_at = datetime(created_at, '+90 days') WHERE expires_at IS NULL;
