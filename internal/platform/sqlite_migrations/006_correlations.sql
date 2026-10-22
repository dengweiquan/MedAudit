-- 006_correlations.sql — M8-1 跨层权限路径关联分析报告存档
-- 报告本体为 JSON（节点/边计数 + 路径列表，逐步含证据事实 ID）。

CREATE TABLE IF NOT EXISTS correlation_reports (
  report_id   TEXT NOT NULL PRIMARY KEY,
  hospital_id TEXT NOT NULL,
  bundle_ids  TEXT NOT NULL,  -- JSON 数组
  path_count  INTEGER NOT NULL DEFAULT 0,
  report      TEXT NOT NULL,  -- JSON：correlation.Report
  created_by  TEXT,
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_correlation_hospital ON correlation_reports (hospital_id);
