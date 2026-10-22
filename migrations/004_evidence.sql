-- 004_evidence.sql — M4-3b 证据加密存储
-- 原始事实包 zip 的加密证据：与 fact_bundles（解析后 JSON）分离保存，
-- 供事后复核原始证据。明文 SHA-256 同时回填 fact_bundles.evidence_digest。

CREATE TABLE IF NOT EXISTS fact_bundle_evidence (
  bundle_id   VARCHAR(64) NOT NULL PRIMARY KEY,
  key_version INT         NOT NULL COMMENT '加密密钥版本；0=明文（仅兼容，不再写入）',
  sha256      CHAR(64)    NOT NULL COMMENT '原始 zip 明文 SHA-256（hex）',
  ciphertext  LONGBLOB    NOT NULL COMMENT 'MAE1 格式 blob：magic|ver|nonce|AES-256-GCM 密文',
  stored_at   TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='事实包原始证据（加密）';
