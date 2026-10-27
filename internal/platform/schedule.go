package platform

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"medaudit/internal/rules"
)

// 定期自动复检：对象级开启。默认口令不落库；开启时口令经证据密钥（AES-256-GCM）
// 加密存于 audit_schedules.cred，仅调度器执行审计时在内存解密，关闭即整行删除。
// 未配置证据密钥时不允许开启。

// ScheduleRetryDelay 复检失败后的重试间隔。
const ScheduleRetryDelay = 24 * time.Hour

// AuditSchedule 一个对象的定期复检设置与最近执行情况（不含口令）。
type AuditSchedule struct {
	AssetID      string `json:"asset_id"`
	HospitalID   string `json:"hospital_id"`
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	CycleDays    int    `json:"cycle_days"`
	BaselineID   string `json:"baseline_id"`
	CreatedBy    string `json:"created_by"`
	UpdatedAt    string `json:"updated_at"`
	NextRunAt    string `json:"next_run_at"`
	LastRunAt    string `json:"last_run_at"`
	LastStatus   string `json:"last_status"`
	LastError    string `json:"last_error"`
	LastBundleID string `json:"last_bundle_id"`
}

// ScheduledAuditMode 资产类型可否定期复检："db"（数据库直连）、"remote"（SSH/WinRM 推送）或 ""。
func ScheduledAuditMode(kind string) string {
	if _, ok := engineByKind[kind]; ok {
		return "db"
	}
	if _, ok := remoteKinds[kind]; ok {
		return "remote"
	}
	return ""
}

func utcNow() time.Time { return time.Now().UTC() }

func fmtUTC(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// SaveSchedule 开启或修改对象的定期复检。password 为空时沿用已保存的口令（首次开启必填）。
func SaveSchedule(db *sql.DB, kr *EvidenceKeyring, assetID string, cycleDays int, password, baselineID, by string) error {
	if kr == nil {
		return fmt.Errorf("未配置证据密钥（MEDAUDIT_EVIDENCE_KEY），无法加密保存口令，不能开启定期复检")
	}
	if cycleDays < 1 || cycleDays > 366 {
		return fmt.Errorf("复检周期须在 1–366 天之间")
	}
	var hospitalID, kind string
	if err := db.QueryRow(`SELECT hospital_id, kind FROM assets WHERE id = ?`, assetID).Scan(&hospitalID, &kind); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("资产 %s 不存在", assetID)
		}
		return err
	}
	if ScheduledAuditMode(kind) == "" {
		return fmt.Errorf("资产类型 %s 不支持定期自动复检", kind)
	}
	if baselineID != "" {
		if _, err := LoadBaseline(db, baselineID); err != nil {
			return fmt.Errorf("基线 %s 不可用: %w", baselineID, err)
		}
	}
	var existing int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_schedules WHERE asset_id = ?`, assetID).Scan(&existing); err != nil {
		return err
	}
	now := utcNow()
	// 下次执行：上次审计 + 周期；从未审计或已逾期则尽快执行。
	next := now
	var last string
	_ = db.QueryRow(`SELECT COALESCE(MAX(imported_at), '') FROM fact_bundles WHERE asset_id = ?`, assetID).Scan(&last)
	if t, ok := parseStoredTime(last); ok {
		if due := t.Add(time.Duration(cycleDays) * 24 * time.Hour); due.After(now) {
			next = due
		}
	}
	if existing == 0 {
		if password == "" {
			return fmt.Errorf("首次开启须填写目标登录口令")
		}
		cred, err := kr.Encrypt([]byte(password))
		if err != nil {
			return err
		}
		_, err = db.Exec(`INSERT INTO audit_schedules (asset_id, hospital_id, cycle_days, cred, baseline_id, created_by, updated_at, next_run_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, assetID, hospitalID, cycleDays, cred, baselineID, by, fmtUTC(now), fmtUTC(next))
		return err
	}
	if password != "" {
		cred, err := kr.Encrypt([]byte(password))
		if err != nil {
			return err
		}
		if _, err := db.Exec(`UPDATE audit_schedules SET cred = ? WHERE asset_id = ?`, cred, assetID); err != nil {
			return err
		}
	}
	_, err := db.Exec(`UPDATE audit_schedules SET cycle_days = ?, baseline_id = ?, updated_at = ?, next_run_at = ?
		WHERE asset_id = ?`, cycleDays, baselineID, fmtUTC(now), fmtUTC(next), assetID)
	return err
}

// DeleteSchedule 关闭定期复检并删除保存的口令。
func DeleteSchedule(db *sql.DB, assetID string) error {
	res, err := db.Exec(`DELETE FROM audit_schedules WHERE asset_id = ?`, assetID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("对象 %s 未开启定期复检", assetID)
	}
	return nil
}

// ListSchedules 列出全部已开启的定期复检。
func ListSchedules(db *sql.DB) ([]AuditSchedule, error) {
	rows, err := db.Query(`SELECT s.asset_id, s.hospital_id, COALESCE(a.name, ''), COALESCE(a.kind, ''), s.cycle_days, s.baseline_id,
		s.created_by, s.updated_at, s.next_run_at, s.last_run_at, s.last_status, s.last_error, s.last_bundle_id
		FROM audit_schedules s LEFT JOIN assets a ON a.id = s.asset_id ORDER BY s.next_run_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditSchedule{}
	for rows.Next() {
		var s AuditSchedule
		if err := rows.Scan(&s.AssetID, &s.HospitalID, &s.Name, &s.Kind, &s.CycleDays, &s.BaselineID,
			&s.CreatedBy, &s.UpdatedAt, &s.NextRunAt, &s.LastRunAt, &s.LastStatus, &s.LastError, &s.LastBundleID); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// auditRunner 执行一次审计（可在测试中替换）。
type auditRunner func(ctx context.Context, mode, assetID, password, baselineID string) (bundleID string, err error)

// Scheduler 定期复检调度器：每隔 Interval 检查到期对象并逐个执行（与一键审计共用串行锁）。
type Scheduler struct {
	DB       *sql.DB
	Keyring  *EvidenceKeyring
	Interval time.Duration
	run      auditRunner

	mu      sync.Mutex
	running map[string]bool
}

// NewScheduler 装配调度器，执行沿用 Web 一键审计 / 远程推送的同一实现。
func NewScheduler(db *sql.DB, reg *rules.Registry, kr *EvidenceKeyring, collectorBin, linuxBin, winBin string, tokens *TokenStore) *Scheduler {
	s := &Scheduler{DB: db, Keyring: kr, Interval: 5 * time.Minute, running: map[string]bool{}}
	s.run = func(ctx context.Context, mode, assetID, password, baselineID string) (string, error) {
		if mode == "db" {
			res, err := RunDBAudit(ctx, db, reg, kr, collectorBin, assetID, password, baselineID, "scheduler")
			if err != nil {
				return "", err
			}
			return res.BundleID, nil
		}
		res, err := RunRemoteAudit(ctx, db, reg, kr, linuxBin, winBin, tokens, assetID, password, baselineID, "scheduler")
		if err != nil {
			return "", err
		}
		return res.BundleID, nil
	}
	return s
}

// Start 后台运行调度循环，ctx 取消即停止。
func (s *Scheduler) Start(ctx context.Context) {
	// 进程重启时把残留的 running 状态复位（上次执行被中断）。
	_, _ = s.DB.Exec(`UPDATE audit_schedules SET last_status = 'failed', last_error = '服务重启，上次执行被中断' WHERE last_status = 'running'`)
	go func() {
		t := time.NewTicker(s.Interval)
		defer t.Stop()
		for {
			s.Tick(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// Tick 执行一轮：到期对象逐个同步执行。
func (s *Scheduler) Tick(ctx context.Context) {
	rows, err := s.DB.Query(`SELECT asset_id FROM audit_schedules WHERE next_run_at <= ? AND last_status <> 'running' ORDER BY next_run_at`,
		fmtUTC(utcNow()))
	if err != nil {
		log.Printf("[scheduler] 查询到期对象失败: %v", err)
		return
	}
	var due []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			due = append(due, id)
		}
	}
	rows.Close()
	for _, id := range due {
		if ctx.Err() != nil {
			return
		}
		_ = s.RunOne(ctx, id)
	}
}

// RunNow 立即异步执行一次（不改变周期设置）。
func (s *Scheduler) RunNow(assetID string) error {
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM audit_schedules WHERE asset_id = ?`, assetID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("对象 %s 未开启定期复检", assetID)
	}
	s.mu.Lock()
	busy := s.running[assetID]
	s.mu.Unlock()
	if busy {
		return fmt.Errorf("对象 %s 正在复检中", assetID)
	}
	go func() { _ = s.RunOne(context.Background(), assetID) }()
	return nil
}

// RunOne 执行一个对象的复检并记录结果、操作日志与失败告警。
func (s *Scheduler) RunOne(ctx context.Context, assetID string) error {
	s.mu.Lock()
	if s.running[assetID] {
		s.mu.Unlock()
		return fmt.Errorf("对象 %s 正在复检中", assetID)
	}
	s.running[assetID] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.running, assetID)
		s.mu.Unlock()
	}()

	var hospitalID, baselineID, kind string
	var cycleDays int
	var cred []byte
	err := s.DB.QueryRow(`SELECT s.hospital_id, s.cycle_days, s.cred, s.baseline_id, COALESCE(a.kind, '')
		FROM audit_schedules s LEFT JOIN assets a ON a.id = s.asset_id WHERE s.asset_id = ?`, assetID).
		Scan(&hospitalID, &cycleDays, &cred, &baselineID, &kind)
	if err != nil {
		return err
	}
	start := utcNow()
	_, _ = s.DB.Exec(`UPDATE audit_schedules SET last_status = 'running', last_run_at = ? WHERE asset_id = ?`, fmtUTC(start), assetID)

	bundleID, runErr := s.execute(ctx, kind, assetID, cred, baselineID)
	status, code, next := "ok", 200, start.Add(time.Duration(cycleDays)*24*time.Hour)
	errMsg := ""
	if runErr != nil {
		status, code, next = "failed", 500, start.Add(ScheduleRetryDelay)
		errMsg = tailRunes(runErr.Error(), 300)
	}
	_, _ = s.DB.Exec(`UPDATE audit_schedules SET last_status = ?, last_error = ?, last_bundle_id = ?, next_run_at = ? WHERE asset_id = ?`,
		status, errMsg, bundleID, fmtUTC(next), assetID)
	note := "定期复检"
	if errMsg != "" {
		note += "：" + errMsg
	}
	_ = AppendOpLog(s.DB, OpEntry{Actor: "scheduler", Method: "RUN", Path: "/scheduler/audit/" + assetID,
		Status: code, ClientIP: "-", Note: note})
	if runErr != nil {
		log.Printf("[scheduler] %s 复检失败: %v", assetID, runErr)
		if _, err := RecordAuditFailedAlert(s.DB, hospitalID, assetID, errMsg); err != nil {
			log.Printf("[scheduler] 失败告警写入失败: %v", err)
		}
	}
	return runErr
}

func (s *Scheduler) execute(ctx context.Context, kind, assetID string, cred []byte, baselineID string) (string, error) {
	mode := ScheduledAuditMode(kind)
	if mode == "" {
		return "", fmt.Errorf("资产不存在或类型 %q 不支持定期复检", kind)
	}
	if s.Keyring == nil {
		return "", fmt.Errorf("证据密钥未配置，无法解密保存的口令")
	}
	pw, err := s.Keyring.Decrypt(cred)
	if err != nil {
		return "", fmt.Errorf("口令解密失败（证据密钥可能已更换），请重新保存口令: %w", err)
	}
	password := string(pw)
	defer func() {
		for i := range pw {
			pw[i] = 0
		}
	}()
	if strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("保存的口令为空")
	}
	if baselineID == "" {
		baselineID = AutoBaseline // 未指定基线：与在线评估一致，自动套用本院基线
	}
	return s.run(ctx, mode, assetID, password, baselineID)
}
