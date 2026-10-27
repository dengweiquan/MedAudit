-- 011 平台操作日志：谁在何时做了什么（写操作、证据/报告下载、登录）。
-- 哈希链防篡改：hash = sha256(prev_hash | 各字段)，改删任一行都会断链。
-- 一键清场不清此表（清场本身也记入）。
CREATE TABLE IF NOT EXISTS op_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         TEXT NOT NULL,
    actor      TEXT NOT NULL,
    method     TEXT NOT NULL,
    path       TEXT NOT NULL,
    status     INTEGER NOT NULL,
    client_ip  TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_op_log_at ON op_log (at);
