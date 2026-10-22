-- MedAudit 平台库初始化（SQLite 版，自 MySQL 版 001_init 翻译，M5）
-- 平台元数据存本地 SQLite 文件，与被核查数据库完全分离。
-- 所有时间统一 UTC（CURRENT_TIMESTAMP）。

CREATE TABLE IF NOT EXISTS hospitals (
  id          TEXT NOT NULL PRIMARY KEY,
  name        TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
  id          TEXT NOT NULL PRIMARY KEY,
  login       TEXT NOT NULL UNIQUE,
  display     TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS role_bindings (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     TEXT NOT NULL REFERENCES users(id),
  hospital_id TEXT NOT NULL REFERENCES hospitals(id),
  role        TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (user_id, hospital_id, role)
);

CREATE TABLE IF NOT EXISTS assets (
  id          TEXT NOT NULL PRIMARY KEY,
  hospital_id TEXT NOT NULL REFERENCES hospitals(id),
  kind        TEXT NOT NULL,  -- host/service/db-oracle/db-sqlserver/db-mysql
  name        TEXT NOT NULL,
  endpoint    TEXT NULL,
  labels      TEXT NULL,      -- JSON
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_assets_hosp ON assets (hospital_id);

CREATE TABLE IF NOT EXISTS collection_plans (
  id          TEXT NOT NULL PRIMARY KEY,
  hospital_id TEXT NOT NULL REFERENCES hospitals(id),
  name        TEXT NOT NULL,
  profile     TEXT NOT NULL,
  spec        TEXT NOT NULL,  -- JSON：不可变计划
  created_by  TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS fact_bundles (
  id              TEXT NOT NULL PRIMARY KEY,
  plan_id         TEXT NOT NULL REFERENCES collection_plans(id),
  hospital_id     TEXT NOT NULL,
  asset_id        TEXT NOT NULL,
  schema_version  TEXT NOT NULL,
  adapter         TEXT NOT NULL,
  execution       TEXT NOT NULL,  -- COMPLETE/PARTIAL/FAILED
  bundle          TEXT NOT NULL,  -- JSON：原始事实包
  evidence_digest TEXT NULL,
  imported_at     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_bundles_asset ON fact_bundles (asset_id);

CREATE TABLE IF NOT EXISTS rules (
  id          TEXT NOT NULL PRIMARY KEY,
  version     TEXT NOT NULL,
  name        TEXT NOT NULL,
  target      TEXT NOT NULL,  -- os-linux/os-windows/db-oracle/db-sqlserver/db-mysql
  spec        TEXT NOT NULL,  -- JSON：版本化规则
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (id, version)
);

CREATE TABLE IF NOT EXISTS findings (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  hospital_id  TEXT NOT NULL,
  bundle_id    TEXT NOT NULL,
  rule_id      TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  subject      TEXT NOT NULL,
  conclusion   TEXT NOT NULL,  -- PASS/FAIL/UNKNOWN/NOT_RUN/NOT_APPLICABLE
  detail       TEXT NULL,      -- JSON
  created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_findings_bundle ON findings (bundle_id);
CREATE INDEX IF NOT EXISTS idx_findings_hosp ON findings (hospital_id);

CREATE TABLE IF NOT EXISTS reports (
  id          TEXT NOT NULL PRIMARY KEY,
  hospital_id TEXT NOT NULL REFERENCES hospitals(id),
  plan_id     TEXT NOT NULL,
  snapshot    TEXT NOT NULL,  -- JSON：不可变报告快照
  created_by  TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  hospital_id TEXT NULL,
  actor       TEXT NOT NULL,
  action      TEXT NOT NULL,
  object_ref  TEXT NULL,
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_hosp ON audit_events (hospital_id);

CREATE TABLE IF NOT EXISTS schema_migrations (
  version     TEXT NOT NULL PRIMARY KEY,
  applied_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO schema_migrations (version) VALUES ('001_init');
