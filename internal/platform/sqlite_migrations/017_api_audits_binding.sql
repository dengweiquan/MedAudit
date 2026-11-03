-- 017_api_audits_binding.sql — M4-4 API 审计报告合规绑定
-- 报告归属的医院与接口资产：合规判定（医疗-12）只认绑定且经核实的报告，
-- 未绑定或老格式报告不纳入通过。存量行两列为空（未绑定），行为不变。

ALTER TABLE api_audit_reports ADD COLUMN hospital_id TEXT NOT NULL DEFAULT '';
ALTER TABLE api_audit_reports ADD COLUMN asset_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_api_audits_asset ON api_audit_reports (asset_id);
