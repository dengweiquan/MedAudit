-- 015 修正 014 老令牌回填（M37-fix-1）：014 按 created_at + 90 天回填，但轮换过的
-- 令牌 created_at 仍是首次生成时间（轮换只更新 updated_at），导致一升级就过期。
-- 仅重算 014 回填过的行（expires_at 恰好等于 created_at + 90 天）且轮换过的行
-- （updated_at 晚于 created_at），按 updated_at + 90 天；新代码按天数铸造的令牌
-- （expires_at 不等于 created_at + 90 天，或未轮换过）不受影响。
UPDATE auth_tokens
SET expires_at = datetime(updated_at, '+90 days')
WHERE expires_at = datetime(created_at, '+90 days')
  AND updated_at > created_at;
