//go:build !windows

package main

import (
	"context"
	"time"

	oslinux "medaudit/internal/collect/os/linux"
	"medaudit/internal/facts"
)

func collectOS(ctx context.Context, hospital, asset, plan string, services []string, sudoersDir string) (*facts.FactBundle, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// M19：未显式指定服务时缺省枚举运行中的 systemd 服务单元，
	// 保证服务类检查（单元文件可写/进程能力集等）有事实可判；
	// 枚举不可用返回空，回退基础采集（相关检查诚实 UNKNOWN）。
	if len(services) == 0 {
		services = oslinux.RunningServices(ctx)
	}
	return oslinux.Collect(ctx, oslinux.Config{
		HospitalID: hospital, AssetID: asset, PlanID: plan,
		Services: services, CollectorVersion: version,
		SudoersDir: sudoersDir,
	})
}
