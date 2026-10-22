-- MedAudit M2：版本化基线（SQLite 版，自 MySQL 版 003_baselines 翻译）
CREATE TABLE IF NOT EXISTS baselines (
  id          TEXT NOT NULL PRIMARY KEY,
  hospital_id TEXT NOT NULL,
  target      TEXT NOT NULL,  -- os-linux/os-windows/db-oracle/db-sqlserver/db-mysql/db-postgres
  version     INTEGER NOT NULL DEFAULT 1,
  spec        TEXT NOT NULL,  -- JSON：{allows:[{subject,kind,value,scope,reason}]}
  created_by  TEXT NULL,
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_baselines_hosp ON baselines (hospital_id);

INSERT OR IGNORE INTO schema_migrations (version) VALUES ('003_baselines');
