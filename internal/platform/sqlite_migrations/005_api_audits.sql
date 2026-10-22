-- 005_api_audits.sql — M4-1 业务接口越权检测报告存档（SQLite 版，自 MySQL 版翻译）
-- 报告本体为 JSON；摘要计数冗余成列便于列表与统计。

CREATE TABLE IF NOT EXISTS api_audit_reports (
  report_id     TEXT NOT NULL PRIMARY KEY,
  target        TEXT NOT NULL,
  execution     TEXT NOT NULL,  -- COMPLETE/PARTIAL
  total         INTEGER NOT NULL,
  pass_count    INTEGER NOT NULL DEFAULT 0,
  fail_count    INTEGER NOT NULL DEFAULT 0,
  unknown_count INTEGER NOT NULL DEFAULT 0,
  not_run_count INTEGER NOT NULL DEFAULT 0,
  report        TEXT NOT NULL,  -- JSON：完整报告（含逐项 checks）
  imported_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_api_audits_target ON api_audit_reports (target);
