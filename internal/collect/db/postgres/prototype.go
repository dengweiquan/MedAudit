// Package postgres 提供 PostgreSQL 权限核查适配器（M4-2）。
// 只用标准目录视图（pg_roles / pg_auth_members / pg_database / pg_class 等），
// 普通登录角色即可读，不读业务表，不依赖 superuser。
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	_ "github.com/lib/pq"
)

// Config 连接配置。只接受白名单字段，由调用方结构化构建。
type Config struct {
	Host string
	Port int
	User string
	// Password 通过 secret_ref / 环境变量提供，不进日志与事实包。
	Password string
	// DBName 连接库：对象级模板（模式/对象 ACL）只覆盖该库；角色与数据库级模板为集群范围。
	DBName         string
	SSLMode        string // 空 = prefer；disable / require / verify-full 等 pq 取值
	ConnectTimeout time.Duration
	QueryTimeout   time.Duration
}

// dsn 以 URL 形式构建（net/url 转义 userinfo，避免口令特殊字符破坏解析）。
func (c Config) dsn() string {
	db := c.DBName
	if db == "" {
		db = "postgres"
	}
	ssl := c.SSLMode
	if ssl == "" {
		ssl = "prefer"
	}
	ct := c.ConnectTimeout
	if ct <= 0 {
		ct = 10 * time.Second
	}
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(c.User, c.Password),
		Host:   net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		Path:   "/" + db,
	}
	q := url.Values{}
	q.Set("sslmode", ssl)
	q.Set("connect_timeout", strconv.Itoa(int(ct.Seconds())))
	// 只读会话：服务端也拒绝写操作，双保险。
	q.Set("default_transaction_read_only", "on")
	u.RawQuery = q.Encode()
	return u.String()
}

// Connect 建立连接并在 ConnectTimeout 内完成 Ping。
func Connect(ctx context.Context, cfg Config) (*sql.DB, error) {
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	db, err := sql.Open("postgres", cfg.dsn())
	if err != nil {
		return nil, fmt.Errorf("postgres open: %w", err)
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, fmt.Errorf("postgres ping: %w", err)
	}
	return db, nil
}
