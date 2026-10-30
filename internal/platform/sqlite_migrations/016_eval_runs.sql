-- 016 评估轮次一等记录（M37-fix3）：最新一轮不再靠时间戳聚类推断。
-- 每次服务端评估先落一行 eval_runs，问题行打 eval_run_id；空轮次（0 问题）
-- 也有轮次行可查，报告汇总才能看到 FAIL 0。旧问题行的轮次号由启动时回填
-- （backfillEvalRuns，按既有 120 秒聚类口径分组，保证旧数据行为不变）。
CREATE TABLE IF NOT EXISTS eval_runs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    bundle_id         TEXT NOT NULL,
    hospital_id       TEXT NOT NULL,
    baseline_mode     TEXT NOT NULL DEFAULT '',
    baselines_applied TEXT NOT NULL DEFAULT '[]',
    total             INTEGER,
    pass              INTEGER,
    fail              INTEGER,
    unknown           INTEGER,
    not_run           INTEGER,
    not_applicable    INTEGER,
    findings_count    INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_eval_runs_bundle ON eval_runs (bundle_id, id);
ALTER TABLE findings ADD COLUMN eval_run_id INTEGER;
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings (eval_run_id);
