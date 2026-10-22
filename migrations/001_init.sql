-- MedAudit 平台库初始化（M0）
-- 独立 MySQL 实例，与被核查数据库完全分离。
-- 所有表使用 utf8mb4；时间统一 UTC。

CREATE TABLE IF NOT EXISTS hospitals (
  id          VARCHAR(64)  NOT NULL PRIMARY KEY,
  name        VARCHAR(255) NOT NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS users (
  id          VARCHAR(64)  NOT NULL PRIMARY KEY,
  login       VARCHAR(128) NOT NULL UNIQUE,
  display     VARCHAR(255) NOT NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS role_bindings (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id     VARCHAR(64)  NOT NULL,
  hospital_id VARCHAR(64)  NOT NULL,
  role        VARCHAR(64)  NOT NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_user_hosp_role (user_id, hospital_id, role),
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (hospital_id) REFERENCES hospitals(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS assets (
  id          VARCHAR(64)  NOT NULL PRIMARY KEY,
  hospital_id VARCHAR(64)  NOT NULL,
  kind        VARCHAR(32)  NOT NULL COMMENT 'host/service/db-oracle/db-sqlserver/db-mysql',
  name        VARCHAR(255) NOT NULL,
  endpoint    VARCHAR(255) NULL,
  labels      JSON NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (hospital_id) REFERENCES hospitals(id),
  INDEX idx_assets_hosp (hospital_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS collection_plans (
  id          VARCHAR(64)  NOT NULL PRIMARY KEY,
  hospital_id VARCHAR(64)  NOT NULL,
  name        VARCHAR(255) NOT NULL,
  profile     VARCHAR(64)  NOT NULL,
  spec        JSON NOT NULL COMMENT '不可变计划：目标/账号引用/窗口/查询限制',
  created_by  VARCHAR(64)  NOT NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (hospital_id) REFERENCES hospitals(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS fact_bundles (
  id            VARCHAR(64)   NOT NULL PRIMARY KEY,
  plan_id       VARCHAR(64)   NOT NULL,
  hospital_id   VARCHAR(64)   NOT NULL,
  asset_id      VARCHAR(64)   NOT NULL,
  schema_version VARCHAR(16)  NOT NULL,
  adapter       VARCHAR(32)   NOT NULL,
  execution     VARCHAR(16)   NOT NULL COMMENT 'COMPLETE/PARTIAL/FAILED',
  bundle        JSON NOT NULL COMMENT '原始事实包',
  evidence_digest VARCHAR(128) NULL,
  imported_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_bundle (id),
  INDEX idx_bundles_asset (asset_id),
  FOREIGN KEY (plan_id) REFERENCES collection_plans(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS rules (
  id          VARCHAR(64)  NOT NULL PRIMARY KEY,
  version     VARCHAR(32)  NOT NULL,
  name        VARCHAR(255) NOT NULL,
  target      VARCHAR(32)  NOT NULL COMMENT 'os-linux/os-windows/db-oracle/db-sqlserver/db-mysql',
  spec        JSON NOT NULL COMMENT '版本化规则：前置字段/判定条件/风险/整改建议',
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_rule_ver (id, version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS findings (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  hospital_id VARCHAR(64) NOT NULL,
  bundle_id   VARCHAR(64) NOT NULL,
  rule_id     VARCHAR(64) NOT NULL,
  rule_version VARCHAR(32) NOT NULL,
  subject     VARCHAR(255) NOT NULL,
  conclusion  VARCHAR(16) NOT NULL COMMENT 'PASS/FAIL/UNKNOWN/NOT_RUN/NOT_APPLICABLE',
  detail      JSON NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_findings_bundle (bundle_id),
  INDEX idx_findings_hosp (hospital_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS reports (
  id          VARCHAR(64)  NOT NULL PRIMARY KEY,
  hospital_id VARCHAR(64)  NOT NULL,
  plan_id     VARCHAR(64)  NOT NULL,
  snapshot    JSON NOT NULL COMMENT '不可变报告快照：范围/结论/例外/版本',
  created_by  VARCHAR(64)  NOT NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (hospital_id) REFERENCES hospitals(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS audit_events (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  hospital_id VARCHAR(64) NULL,
  actor       VARCHAR(128) NOT NULL,
  action      VARCHAR(64)  NOT NULL,
  object_ref  VARCHAR(255) NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_audit_hosp (hospital_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version     VARCHAR(32) NOT NULL PRIMARY KEY,
  applied_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO schema_migrations (version) VALUES ('001_init');
