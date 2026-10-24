-- 010 超级令牌（M32）：部署级令牌，只存 bcrypt 哈希，单行 name='super'。
CREATE TABLE IF NOT EXISTS auth_tokens (
    name       TEXT NOT NULL PRIMARY KEY,
    token_hash TEXT NOT NULL,
    disabled   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
