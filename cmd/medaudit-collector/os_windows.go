//go:build windows

package main

import (
	"context"
	"time"

	oswin "medaudit/internal/collect/os/windows"
	"medaudit/internal/facts"
)

func collectOS(ctx context.Context, hospital, asset, plan string, services []string, sudoersDir string) (*facts.FactBundle, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	return oswin.Collect(ctx, oswin.Config{
		HospitalID: hospital, AssetID: asset, PlanID: plan,
		Services: services, CollectorVersion: version,
	})
}
