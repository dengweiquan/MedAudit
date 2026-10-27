-- 012 告警：权限漂移（新增授权/角色/主体）与定期复检失败。
CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    hospital_id    TEXT NOT NULL,
    asset_id       TEXT NOT NULL,
    kind           TEXT NOT NULL,          -- drift | audit_failed
    bundle_id      TEXT NOT NULL DEFAULT '',
    prev_bundle_id TEXT NOT NULL DEFAULT '',
    added_count    INTEGER NOT NULL DEFAULT 0,
    title          TEXT NOT NULL,
    detail         TEXT NOT NULL DEFAULT '', -- JSON：样例条目或错误信息
    created_at     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    acked_by       TEXT NOT NULL DEFAULT '',
    acked_at       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alerts_open ON alerts (acked_at, id);
CREATE INDEX IF NOT EXISTS idx_alerts_asset ON alerts (asset_id);
