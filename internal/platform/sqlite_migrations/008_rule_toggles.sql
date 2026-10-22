-- 008_rule_toggles.sql — M17 规则启停（本站作用域，单院部署）：
-- 工程师关闭的检查项在评估时整体跳过（不产生问题、报告不体现），
-- 与基线分工：基线豁免单个主体，启停关闭整项检查。操作留痕。
CREATE TABLE IF NOT EXISTS rule_toggles (
  rule_id    TEXT NOT NULL PRIMARY KEY,
  enabled    INTEGER NOT NULL DEFAULT 1,
  reason     TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
