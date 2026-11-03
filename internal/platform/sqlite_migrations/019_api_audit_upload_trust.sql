-- API 审计报告上传可信度：1 = 持有效会话上传（认证上传），0 = 历史遗留
-- 未认证上传。合规判定只采信认证上传的报告；未认证报告可保留查阅，
-- 但条款一律 unknown，不作为可信合规 PASS。
ALTER TABLE api_audit_reports ADD COLUMN upload_authenticated INTEGER NOT NULL DEFAULT 0;
