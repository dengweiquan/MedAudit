package oracle

import (
	"time"

	go_ora "github.com/sijms/go-ora/v2"
)

// Config 连接配置。只接受白名单字段，由调用方结构化构建，
// 不接受任意 TNS/连接描述符；Service 为登记的服务名。
type Config struct {
	Host string
	Port int
	// Service 登记的服务名（如 ARKPDB1），禁止任意 TNS 地址。
	Service string
	User    string
	// Password 通过 secret_ref / 环境变量提供，不进日志与事实包。
	Password       string
	ConnectTimeout time.Duration
	QueryTimeout   time.Duration
}

// connString 用白名单字段构建连接串（go-ora 纯 Go 驱动，BuildUrl 负责转义）。
func (c Config) connString() string {
	return go_ora.BuildUrl(c.Host, c.Port, c.Service, c.User, c.Password, nil)
}
