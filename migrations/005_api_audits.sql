-- 005_api_audits.sql — M4-1 业务接口越权检测报告存档
-- 报告本体为 JSON；摘要计数冗余成列便于列表与统计。

CREATE TABLE IF NOT EXISTS api_audit_reports (
  report_id     VARCHAR(64)  NOT NULL PRIMARY KEY,
  target        VARCHAR(255) NOT NULL,
  execution     VARCHAR(16)  NOT NULL COMMENT 'COMPLETE/PARTIAL',
  total         INT          NOT NULL,
  pass_count    INT          NOT NULL DEFAULT 0,
  fail_count    INT          NOT NULL DEFAULT 0,
  unknown_count INT          NOT NULL DEFAULT 0,
  not_run_count INT          NOT NULL DEFAULT 0,
  report        JSON         NOT NULL COMMENT '完整报告（含逐项 checks）',
  imported_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_api_audits_target (target)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='业务接口越权检测报告';
