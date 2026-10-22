-- MedAudit M2：版本化基线
CREATE TABLE IF NOT EXISTS baselines (
  id          VARCHAR(64)  NOT NULL PRIMARY KEY,
  hospital_id VARCHAR(64)  NOT NULL,
  target      VARCHAR(32)  NOT NULL COMMENT 'os-linux/os-windows/db-oracle/db-sqlserver/db-mysql',
  version     INT NOT NULL DEFAULT 1,
  spec        JSON NOT NULL COMMENT '{allows:[{subject,kind,value,scope,reason}]}',
  created_by  VARCHAR(128) NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_baselines_hosp (hospital_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO schema_migrations (version) VALUES ('003_baselines');
