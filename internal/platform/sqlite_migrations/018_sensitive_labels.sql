-- 018_sensitive_labels.sql — M5-5 敏感对象标记（表/列级）
-- 只存对象标识与敏感类别，不存真实患者数据。自然键唯一（医院/资产/库/
-- 模式/表/列），重复创建幂等；编辑时 version +1，报告快照记录该版本，
-- 标签变化后新报告用新快照，旧报告快照不变。

CREATE TABLE IF NOT EXISTS sensitive_labels (
  id            TEXT NOT NULL PRIMARY KEY,
  hospital_id   TEXT NOT NULL REFERENCES hospitals(id),
  asset_id      TEXT NOT NULL REFERENCES assets(id),
  database_name TEXT NOT NULL DEFAULT '',
  schema_name   TEXT NOT NULL,
  table_name    TEXT NOT NULL,
  column_name   TEXT NOT NULL DEFAULT '',
  category      TEXT NOT NULL,
  version       INTEGER NOT NULL DEFAULT 1,
  created_by    TEXT NOT NULL DEFAULT '',
  created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (hospital_id, asset_id, database_name, schema_name, table_name, column_name)
);
CREATE INDEX IF NOT EXISTS idx_sensitive_labels_asset ON sensitive_labels (asset_id);
CREATE INDEX IF NOT EXISTS idx_sensitive_labels_hosp ON sensitive_labels (hospital_id);
