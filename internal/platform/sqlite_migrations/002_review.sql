-- MedAudit M2：人工复核、例外、整改复测（SQLite 版，自 MySQL 版 002_review 翻译）
-- 技术结论（findings）与人工决定分开存储；例外不改写技术事实。

CREATE TABLE IF NOT EXISTS reviews (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id  INTEGER NOT NULL REFERENCES findings(id),
  hospital_id TEXT NOT NULL,
  decision    TEXT NOT NULL,  -- confirmed/false_positive/exception_requested
  comment     TEXT NULL,
  reviewer    TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_reviews_finding ON reviews (finding_id);

CREATE TABLE IF NOT EXISTS exceptions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  hospital_id TEXT NOT NULL,
  subject     TEXT NOT NULL,
  rule_id     TEXT NOT NULL,
  reason      TEXT NOT NULL,
  owner       TEXT NOT NULL,
  expires_at  TEXT NOT NULL,  -- DATE（YYYY-MM-DD）
  status      TEXT NOT NULL DEFAULT 'active',  -- active/expired/revoked
  created_by  TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_exceptions_hosp ON exceptions (hospital_id);

CREATE TABLE IF NOT EXISTS remediations (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  hospital_id TEXT NOT NULL,
  finding_id  INTEGER NOT NULL REFERENCES findings(id),
  action      TEXT NOT NULL,  -- 整改措施描述（经现有变更流程执行）
  status      TEXT NOT NULL DEFAULT 'pending',  -- pending/done
  acted_by    TEXT NOT NULL,
  acted_at    TEXT NULL,
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_remediation_finding ON remediations (finding_id);

CREATE TABLE IF NOT EXISTS retests (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  hospital_id TEXT NOT NULL,
  finding_id  INTEGER NOT NULL REFERENCES findings(id),
  bundle_id   TEXT NOT NULL,  -- 复测使用的新事实包
  conclusion  TEXT NOT NULL,  -- 复测技术结论
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_retest_finding ON retests (finding_id);

-- findings 表补充复核状态列（幂等性由迁移执行器按版本保证）
ALTER TABLE findings ADD COLUMN review_status TEXT NOT NULL DEFAULT 'pending';
-- review_status 取值：pending/confirmed/false_positive/exception

INSERT OR IGNORE INTO schema_migrations (version) VALUES ('002_review');
