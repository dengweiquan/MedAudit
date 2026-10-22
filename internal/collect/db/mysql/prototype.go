// Package mysql 提供 MySQL 权限核查适配器。
// M0：连接原型（Connect + Ping + 版本查询 + 最小事实包）。
package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"medaudit/internal/facts"

	_ "github.com/go-sql-driver/mysql"
)

// Config 连接配置。只接受白名单字段，由调用方结构化构建，
// 禁止传入任意 DSN 参数、多语句、文件导入等。
type Config struct {
	Host string
	Port int
	User string
	// Password 通过 secret_ref / 环境变量提供，不进日志与事实包。
	Password       string
	DBName         string
	ConnectTimeout time.Duration
	QueryTimeout   time.Duration
}

// dsn 用白名单字段构建连接串，显式关闭多语句与文件导入。
func (c Config) dsn() string {
	db := c.DBName
	if db == "" {
		db = "mysql"
	}
	// interpolateParams=false, multiStatements=false 默认即关闭；显式写出以防驱动默认值变化。
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?timeout=%ds&readTimeout=%ds&writeTimeout=%ds&multiStatements=false&allowCleartextPasswords=false&interpolateParams=false",
		c.User, c.Password, c.Host, c.Port, db,
		int(c.ConnectTimeout.Seconds()), int(c.QueryTimeout.Seconds()), int(c.QueryTimeout.Seconds()))
}

// Connect 建立连接并在 ConnectTimeout 内完成 Ping。
func Connect(ctx context.Context, cfg Config) (*sql.DB, error) {
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	db, err := sql.Open("mysql", cfg.dsn())
	if err != nil {
		return nil, fmt.Errorf("mysql open: %w", err)
	}
	// 小连接池：原型阶段单连接即可。
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, fmt.Errorf("mysql ping: %w", err)
	}
	return db, nil
}

// PrototypeCollect M0 原型：查询实例版本，输出带收据的最小事实包。
// 身份说明：collector_identity 为本原型连接所用账号；target_identity 在原型
// 阶段填同一连接账号并标注来源 unknown，M1 由资产登记的被核查账号替换。
func PrototypeCollect(ctx context.Context, db *sql.DB, cfg Config, collectorVersion string) (*facts.FactBundle, error) {
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = 10 * time.Second
	}
	now := time.Now().UTC().Truncate(time.Second)
	b := &facts.FactBundle{
		SchemaVersion: facts.SchemaVersion,
		BundleID:      "bundle-mysql-proto-001",
		PlanID:        "plan-m0-proto",
		Collector: facts.CollectorInfo{
			Name:           "medaudit-collector",
			Version:        collectorVersion,
			Adapter:        facts.TargetDBMySQL,
			AdapterVersion: "0.1.0-m0",
		},
		CollectedAt: facts.TimeRange{Started: now},
		Scope: facts.Scope{
			HospitalID: "h-m0-test",
			AssetID:    "db-mysql-proto",
			TargetType: facts.TargetDBMySQL,
			Profile:    "m0-prototype",
		},
		Identities: facts.Identities{
			CollectorIdentity: cfg.User + "@collector",
			TargetIdentity:    cfg.User + "@target",
			AppIdentitySource: "unknown",
		},
	}

	// 模板 mysql.instance_version v1
	rStart := time.Now()
	qctx, cancel := context.WithTimeout(ctx, cfg.QueryTimeout)
	var version string
	qerr := db.QueryRowContext(qctx, "SELECT VERSION()").Scan(&version)
	cancel()
	rEnd := time.Now()

	receipt := facts.Receipt{
		TemplateID:      "mysql.instance_version",
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
			FactID:     "fact-mysql-version-001",
			Kind:       facts.FactIdentity,
			Subject:    fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			Status:     facts.StatusObserved,
			Source:     "mysql.instance_version",
			Attributes: map[string]string{"version": version},
		},
	}
	b.Receipts = []facts.Receipt{receipt}
	b.Execution = facts.ExecutionComplete
	b.CollectedAt.Finished = time.Now().UTC().Truncate(time.Second)
	return b, nil
}
