-- MedAudit M2：人工复核、例外、整改复测
-- 技术结论（findings）与人工决定分开存储；例外不改写技术事实。

CREATE TABLE IF NOT EXISTS reviews (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  finding_id  BIGINT NOT NULL,
  hospital_id VARCHAR(64) NOT NULL,
  decision    VARCHAR(32) NOT NULL COMMENT 'confirmed/false_positive/exception_requested',
  comment     TEXT NULL,
  reviewer    VARCHAR(128) NOT NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_reviews_finding (finding_id),
  FOREIGN KEY (finding_id) REFERENCES findings(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS exceptions (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  hospital_id VARCHAR(64) NOT NULL,
  subject     VARCHAR(255) NOT NULL,
  rule_id     VARCHAR(64) NOT NULL,
  reason      TEXT NOT NULL,
  owner       VARCHAR(128) NOT NULL,
  expires_at  DATE NOT NULL,
  status      VARCHAR(32) NOT NULL DEFAULT 'active' COMMENT 'active/expired/revoked',
  created_by  VARCHAR(128) NOT NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_exceptions_hosp (hospital_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS remediations (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  hospital_id VARCHAR(64) NOT NULL,
  finding_id  BIGINT NOT NULL,
  action      TEXT NOT NULL COMMENT '整改措施描述（经现有变更流程执行）',
  status      VARCHAR(32) NOT NULL DEFAULT 'pending' COMMENT 'pending/done',
  acted_by    VARCHAR(128) NOT NULL,
  acted_at    TIMESTAMP NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_remediation_finding (finding_id),
  FOREIGN KEY (finding_id) REFERENCES findings(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS retests (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  hospital_id VARCHAR(64) NOT NULL,
  finding_id  BIGINT NOT NULL,
  bundle_id   VARCHAR(64) NOT NULL COMMENT '复测使用的新事实包',
  conclusion  VARCHAR(16) NOT NULL COMMENT '复测技术结论',
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_retest_finding (finding_id),
  FOREIGN KEY (finding_id) REFERENCES findings(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- findings 表补充复核状态列（幂等）
ALTER TABLE findings ADD COLUMN review_status VARCHAR(32) NOT NULL DEFAULT 'pending'
  COMMENT 'pending/confirmed/false_positive/exception';

INSERT IGNORE INTO schema_migrations (version) VALUES ('002_review');
