//go:build windows

package oracle

import (
	"context"
	"database/sql"
	"fmt"

	"medaudit/internal/facts"
)

// Windows 平台不支持 godror（CGO Oracle 客户端无 Windows 构建）。
// Oracle 采集应在 Linux 采集器上运行，目标为远程 Oracle 实例。
func Connect(ctx context.Context, cfg Config) (*sql.DB, error) {
	return nil, fmt.Errorf("oracle 适配器不支持 Windows 采集器（godror 无 Windows 构建），请在 Linux 上运行")
}

// PrototypeCollect Windows 桩。
func PrototypeCollect(ctx context.Context, db *sql.DB, cfg Config, collectorVersion string) (*facts.FactBundle, error) {
	return nil, fmt.Errorf("oracle 适配器不支持 Windows 采集器")
}
