// Package sqlserver 提供 SQL Server 权限核查适配器。
// M0：连接原型（Connect + Ping + 版本查询 + 最小事实包）。
package sqlserver

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"medaudit/internal/facts"

	_ "github.com/microsoft/go-mssqldb"
)

// Config 连接配置。只接受白名单字段，由调用方结构化构建，
// 不接受任意驱动参数；认证方式（SQL/Windows）由 M1 按登记冻结。
type Config struct {
	Host string
	Port int
	User string
	// Password 通过 secret_ref / 环境变量提供，不进日志与事实包。
	Password       string
	DBName         string
	ConnectTimeout time.Duration
	QueryTimeout   time.Duration
	// Encrypt: "disable" 仅允许在已登记的受控明文环境显式使用并形成缺口记录。
	Encrypt string
}

// connString 用白名单字段构建连接串。
// 用 net/url 构建并转义 userinfo：Windows 身份验证的用户名为 DOMAIN\user 形式，
// 反斜杠未经转义会使 url.Parse 失败；转义后驱动解码得到原始用户名，
// 含反斜杠即触发 Unix 平台默认的 NTLM 集成认证（无反斜杠则回退 SQL 认证）。
// SQL 认证同样受益：口令含 @、: 等字符不再破坏 DSN 结构。
func (c Config) connString() string {
	db := c.DBName
	if db == "" {
		db = "master"
	}
	enc := c.Encrypt
	if enc == "" {
		enc = "true"
	}
	u := &url.URL{
		Scheme: "sqlserver",
		User:   url.UserPassword(c.User, c.Password),
		Host:   fmt.Sprintf("%s:%d", c.Host, c.Port),
	}
	q := url.Values{}
	q.Set("database", db)
	q.Set("dial timeout", strconv.Itoa(int(c.ConnectTimeout.Seconds())))
	q.Set("encrypt", enc)
	q.Set("trustServerCertificate", "true")
	u.RawQuery = q.Encode()
	return u.String()
}

// Connect 建立连接并在 ConnectTimeout 内完成 Ping。
func Connect(ctx context.Context, cfg Config) (*sql.DB, error) {
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 15 * time.Second
	}
	db, err := sql.Open("sqlserver", cfg.connString())
	if err != nil {
		return nil, fmt.Errorf("sqlserver open: %w", err)
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlserver ping: %w", err)
	}
	return db, nil
}

// PrototypeCollect M0 原型：查询实例版本与当前登录，输出带收据的最小事实包。
func PrototypeCollect(ctx context.Context, db *sql.DB, cfg Config, collectorVersion string) (*facts.FactBundle, error) {
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = 15 * time.Second
	}
	now := time.Now().UTC().Truncate(time.Second)
	b := &facts.FactBundle{
		SchemaVersion: facts.SchemaVersion,
		BundleID:      "bundle-mssql-proto-001",
		PlanID:        "plan-m0-proto",
		Collector: facts.CollectorInfo{
			Name:           "medaudit-collector",
			Version:        collectorVersion,
			Adapter:        facts.TargetDBSQLSrv,
			AdapterVersion: "0.1.0-m0",
		},
		CollectedAt: facts.TimeRange{Started: now},
		Scope: facts.Scope{
			HospitalID: "h-m0-test",
			AssetID:    "db-mssql-proto",
			TargetType: facts.TargetDBSQLSrv,
			Profile:    "m0-prototype",
		},
		Identities: facts.Identities{
			CollectorIdentity: cfg.User + "@collector",
			TargetIdentity:    cfg.User + "@target",
			AppIdentitySource: "unknown",
		},
	}

	// 模板 mssql.instance_version v1
	rStart := time.Now()
	qctx, cancel := context.WithTimeout(ctx, cfg.QueryTimeout)
	var version, login string
	qerr := db.QueryRowContext(qctx, "SELECT @@VERSION, SUSER_SNAME()").Scan(&version, &login)
	cancel()
	rEnd := time.Now()

	receipt := facts.Receipt{
		TemplateID:      "mssql.instance_version",
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

	b.Scope.TargetVersion = firstLine(version)
	b.Facts = []facts.Fact{
		{
			FactID:     "fact-mssql-version-001",
			Kind:       facts.FactIdentity,
			Subject:    fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			Status:     facts.StatusObserved,
			Source:     "mssql.instance_version",
			Attributes: map[string]string{"version": firstLine(version), "login": login},
		},
	}
	b.Receipts = []facts.Receipt{receipt}
	b.Execution = facts.ExecutionComplete
	b.CollectedAt.Finished = time.Now().UTC().Truncate(time.Second)
	return b, nil
}

func firstLine(s string) string {
	for i, r := range s {
		if r == '\n' || r == '\r' {
			return s[:i]
		}
	}
	if len(s) > 120 {
		return s[:120]
	}
	return s
}
