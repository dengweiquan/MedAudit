package oracle

import (
	"fmt"
	"time"
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

// connString 用白名单字段构建 EZCONNECT 连接串。
func (c Config) connString() string {
	// godror 支持 user/pass@host:port/service 格式。
	return fmt.Sprintf("%s/%s@%s:%d/%s",
		c.User, c.Password, c.Host, c.Port, c.Service)
}
