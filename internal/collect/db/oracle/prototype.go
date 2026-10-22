// Package oracle 提供 Oracle 权限核查适配器。
// M0：连接原型（Connect + 版本查询 + 最小事实包）。
//
// 驱动为纯 Go 实现（go-ora），不依赖 Oracle Instant Client，
// Linux / Windows 采集器同一实现，零外部依赖。
package oracle

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"medaudit/internal/facts"

	_ "github.com/sijms/go-ora/v2"

	"errors"
	"strings"
)

// Connect 建立连接并在 ConnectTimeout 内完成 Ping。
func Connect(ctx context.Context, cfg Config) (*sql.DB, error) {
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 15 * time.Second
	}
	db, err := sql.Open("oracle", cfg.connString())
	if err != nil {
		return nil, fmt.Errorf("oracle open: %w", err)
	}
	// 小连接池。
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, fmt.Errorf("oracle ping: %w", cleanOracleErr(err, cfg.Password))
	}
	return db, nil
}

// PrototypeCollect M0 原型：查询实例版本与当前用户，输出带收据的最小事实包。
// 注意：原型使用专用低权限测试账号（medaudit_proto），不以 SYSDBA 为默认采集前提。
func PrototypeCollect(ctx context.Context, db *sql.DB, cfg Config, collectorVersion string) (*facts.FactBundle, error) {
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = 15 * time.Second
	}
	now := time.Now().UTC().Truncate(time.Second)
	b := &facts.FactBundle{
		SchemaVersion: facts.SchemaVersion,
		BundleID:      "bundle-ora-proto-001",
		PlanID:        "plan-m0-proto",
		Collector: facts.CollectorInfo{
			Name:           "medaudit-collector",
			Version:        collectorVersion,
			Adapter:        facts.TargetDBOracle,
			AdapterVersion: "0.1.0-m0",
		},
		CollectedAt: facts.TimeRange{Started: now},
		Scope: facts.Scope{
			HospitalID: "h-m0-test",
			AssetID:    "db-ora-proto",
			TargetType: facts.TargetDBOracle,
			Instance:   "ARK19C",
			Container:  cfg.Service,
			Profile:    "m0-prototype",
		},
		Identities: facts.Identities{
			CollectorIdentity: cfg.User + "@collector",
			TargetIdentity:    cfg.User + "@target",
			AppIdentitySource: "unknown",
		},
	}

	// 模板 ora.instance_version v1
	rStart := time.Now()
	qctx, cancel := context.WithTimeout(ctx, cfg.QueryTimeout)
	var version, dbUser string
	qerr := db.QueryRowContext(qctx, "SELECT version, USER FROM v$instance").Scan(&version, &dbUser)
	cancel()
	rEnd := time.Now()

	receipt := facts.Receipt{
		TemplateID:      "ora.instance_version",
		TemplateVersion: "1",
		Started:         rStart.UTC().Truncate(time.Second),
		Finished:        rEnd.UTC().Truncate(time.Second),
		DurationMs:      rEnd.Sub(rStart).Milliseconds(),
		Status:          "ok",
		Visibility:      "full",
	}
	if qerr != nil {
		receipt.Status = "failed"
		receipt.ErrorStage = "query"
		b.Receipts = []facts.Receipt{receipt}
		b.Execution = facts.ExecutionFailed
		b.CollectedAt.Finished = time.Now().UTC().Truncate(time.Second)
		return b, fmt.Errorf("version query: %w", qerr)
	}
	receipt.RowCount = 1

	b.Scope.TargetVersion = version
	b.Facts = []facts.Fact{
		{
			FactID:     "fact-ora-version-001",
			Kind:       facts.FactIdentity,
			Subject:    fmt.Sprintf("%s:%d/%s", cfg.Host, cfg.Port, cfg.Service),
			Status:     facts.StatusObserved,
			Source:     "ora.instance_version",
			Attributes: map[string]string{"version": version, "db_user": dbUser},
		},
	}
	b.Receipts = []facts.Receipt{receipt}
	b.Execution = facts.ExecutionComplete
	b.CollectedAt.Finished = time.Now().UTC().Truncate(time.Second)
	return b, nil
}

// cleanOracleErr 清洗连接错误：抹去可能混入的口令等敏感串，
// 只保留可读结论（如 ORA-01017: ...），避免内部参数直达界面。
func cleanOracleErr(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	str := err.Error()
	for _, s := range secrets {
		if s != "" {
			str = strings.ReplaceAll(str, s, "***")
		}
	}
	return errors.New(str)
}
