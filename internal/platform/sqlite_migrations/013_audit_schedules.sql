-- 013 定期自动复检：按对象开启，口令以证据密钥 AES-256-GCM 加密保存，关闭即删除。
CREATE TABLE IF NOT EXISTS audit_schedules (
    asset_id       TEXT NOT NULL PRIMARY KEY,
    hospital_id    TEXT NOT NULL,
    cycle_days     INTEGER NOT NULL,
    cred           BLOB NOT NULL,
    baseline_id    TEXT NOT NULL DEFAULT '',
    created_by     TEXT NOT NULL DEFAULT '',
    updated_at     TEXT NOT NULL,
    next_run_at    TEXT NOT NULL,
    last_run_at    TEXT NOT NULL DEFAULT '',
    last_status    TEXT NOT NULL DEFAULT '',  -- '' | running | ok | failed
    last_error     TEXT NOT NULL DEFAULT '',
    last_bundle_id TEXT NOT NULL DEFAULT ''
);
