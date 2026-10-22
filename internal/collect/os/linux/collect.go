package linux

import (
	"context"
	"fmt"
	"os"
	"time"

	"medaudit/internal/facts"
)

// Config Linux 采集配置。采集范围限定在指定服务及其关联对象，
// 不做无边界全机遍历。
type Config struct {
	Node     string // 节点名，默认取 hostname
	HospitalID string
	AssetID  string
	PlanID   string
	// Services systemd 单元名（如 cron.service）；为空则只做本机基础采集
	//（CLI 层在用户未指定时以 RunningServices 的枚举结果填充，见 cmd 层）。
	Services []string
	CollectorVersion string
	// SudoersDir sudoers 所在根目录，默认 /etc；离线根目录分析时可指定挂载路径。
	SudoersDir string
}

// Collect 执行 Linux OS 事实采集，输出版本化事实包。
func Collect(ctx context.Context, cfg Config) (*facts.FactBundle, error) {
	now := time.Now().UTC().Truncate(time.Second)
	node := cfg.Node
	if node == "" {
		if h, err := os.Hostname(); err == nil {
			node = h
		} else {
			node = "unknown"
		}
	}
	bootID, bootErr := BootID()

	b := &facts.FactBundle{
		SchemaVersion: facts.SchemaVersion,
		BundleID:      "bundle-os-linux-" + now.Format("20060102-150405"),
		PlanID:        cfg.PlanID,
		Collector: facts.CollectorInfo{
			Name:           "medaudit-collector",
			Version:        cfg.CollectorVersion,
			Adapter:        facts.TargetOSLinux,
			AdapterVersion: "0.1.0-m1",
		},
		CollectedAt: facts.TimeRange{Started: now},
		Scope: facts.Scope{
			HospitalID: cfg.HospitalID,
			AssetID:    cfg.AssetID,
			TargetType: facts.TargetOSLinux,
			Profile:    "m1-os-basic",
		},
		Identities: facts.Identities{
			CollectorIdentity: fmt.Sprintf("uid=%d@collector", os.Geteuid()),
			TargetIdentity:    "host:" + node,
			AppIdentitySource: "unknown",
		},
	}
	if cfg.PlanID == "" {
		b.PlanID = "plan-m1-os"
	}

	execStatus := facts.ExecutionComplete
	addReceipt := func(r facts.Receipt) { b.Receipts = append(b.Receipts, r) }

	// 模板 linux.boot_id v1
	rStart := time.Now()
	receipt := facts.Receipt{
		TemplateID: "linux.boot_id", TemplateVersion: "1",
		Started: rStart.UTC().Truncate(time.Second),
		Status: "ok", Visibility: "full",
	}
	if bootErr != nil {
		receipt.Status = "failed"
		receipt.ErrorStage = "read"
		bootID = ""
	} else {
		receipt.RowCount = 1
	}
	receipt.Finished = time.Now().UTC().Truncate(time.Second)
	receipt.DurationMs = receipt.Finished.Sub(receipt.Started).Milliseconds()
	addReceipt(receipt)
	b.Facts = append(b.Facts, facts.Fact{
		FactID: "fact-boot-id", Kind: facts.FactIdentity,
		Subject: node, Status: facts.StatusObserved, Source: "linux.boot_id",
		Attributes: map[string]string{"boot_id": bootID, "node": node},
	})
	if bootErr != nil {
		b.Facts[len(b.Facts)-1].Status = facts.StatusUnsupported
		b.Facts[len(b.Facts)-1].Attributes["error"] = bootErr.Error()
	}

	// 逐服务采集：单元信息 → 进程 → 文件权限
	for i, svc := range cfg.Services {
		if err := ctx.Err(); err != nil {
			break
		}
		collectService(ctx, b, node, bootID, svc, i, &execStatus, addReceipt)
	}

	// 模板 linux.sudo v1：sudoers 授权规格
	collectSudo(b, cfg.SudoersDir, addReceipt, &execStatus)
	collectPasswdGroups(b, cfg.SudoersDir, addReceipt, &execStatus)

	b.Execution = execStatus
	b.CollectedAt.Finished = time.Now().UTC().Truncate(time.Second)
	return b, nil
}

// collectService 采集单个 systemd 服务的事实。
func collectService(ctx context.Context, b *facts.FactBundle, node, bootID, svc string, idx int,
	execStatus *facts.ExecutionStatus, addReceipt func(facts.Receipt)) {

	// 模板 linux.unit_info v1
	rStart := time.Now()
	unit, uerr := ReadUnit(ctx, svc)
	receipt := facts.Receipt{
		TemplateID: "linux.unit_info", TemplateVersion: "1",
		Started: rStart.UTC().Truncate(time.Second),
		Status: "ok", Visibility: "full",
	}
	factBase := fmt.Sprintf("fact-unit-%d", idx)
	if uerr != nil {
		receipt.Status = "failed"
		receipt.ErrorStage = "systemctl"
		receipt.Finished = time.Now().UTC().Truncate(time.Second)
		receipt.DurationMs = receipt.Finished.Sub(receipt.Started).Milliseconds()
		addReceipt(receipt)
		b.Facts = append(b.Facts, facts.Fact{
			FactID: factBase, Kind: facts.FactServiceConfig, Subject: svc,
			Status: facts.StatusUnsupported, Source: "linux.unit_info",
			Attributes: map[string]string{"error": uerr.Error()},
		})
		*execStatus = facts.ExecutionPartial
		return
	}
	receipt.RowCount = 1
	receipt.Finished = time.Now().UTC().Truncate(time.Second)
	receipt.DurationMs = receipt.Finished.Sub(receipt.Started).Milliseconds()
	addReceipt(receipt)

	b.Facts = append(b.Facts, facts.Fact{
		FactID: factBase, Kind: facts.FactServiceConfig, Subject: svc,
		Status: facts.StatusObserved, Source: "linux.unit_info",
		Attributes: map[string]string{
			"active_state": unit.ActiveState, "sub_state": unit.SubState,
			"user": unit.User, "group": unit.Group,
			"fragment": unit.FragmentPath,
		},
	})

	// 单元文件权限
	collectFilePerms(b, fmt.Sprintf("fact-unitfile-%d", idx), unit.FragmentPath, "linux.unit_info")

	pids := []int{}
	if unit.MainPID > 0 {
		pids = append(pids, unit.MainPID)
	}
	if unit.ExecMainPID > 0 && unit.ExecMainPID != unit.MainPID {
		pids = append(pids, unit.ExecMainPID)
	}

	// 模板 linux.proc_scan v1：采集前后用 starttime 核对 PID 复用
	rStart = time.Now()
	procReceipt := facts.Receipt{
		TemplateID: "linux.proc_scan", TemplateVersion: "1",
		Started: rStart.UTC().Truncate(time.Second),
		Status: "ok", Visibility: "full",
	}
	for j, pid := range pids {
		p, perr := ReadProc(pid)
		if perr != nil {
			b.Facts = append(b.Facts, facts.Fact{
				FactID: fmt.Sprintf("fact-proc-%d-%d", idx, j),
				Kind: facts.FactProcess, Subject: fmt.Sprintf("pid:%d", pid),
				Status: facts.StatusPermissionDenied, Source: "linux.proc_scan",
				Attributes: map[string]string{"error": perr.Error()},
			})
			procReceipt.Status = "partial"
			continue
		}
		// 采集后复核 starttime，防止 PID 复用拼接成错误证据
		p2, err2 := ReadProc(pid)
		status := facts.StatusObserved
		if err2 != nil || p2.StartTime != p.StartTime || p2.Comm != p.Comm {
			status = facts.StatusInconsistent
			procReceipt.Status = "partial"
		}
		attrs := map[string]string{
			"proc_key": ProcKey(node, bootID, p),
			"comm":     p.Comm,
			"state":    p.State,
			"ppid":     fmt.Sprintf("%d", p.PPID),
			"euid":     fmt.Sprintf("%d", p.EUID),
			"egid":     fmt.Sprintf("%d", p.EGID),
			"capeff":   fmt.Sprintf("%#x", p.CapEff),
			"caps":     fmt.Sprintf("%v", DecodeCaps(p.CapEff)),
			"exe":      p.Exe,
		}
		if p.EUID == 0 {
			attrs["role"] = "root"
		} else if !IsFullRoot(p.CapEff) && len(DecodeCaps(p.CapEff)) > 0 {
			attrs["role"] = "nonroot-with-caps"
		} else {
			attrs["role"] = "nonroot"
		}
		// 配置用户与实际 EUID 交叉：启动者不等于运行者
		if unit.User != "" {
			attrs["configured_user"] = unit.User
		}
		b.Facts = append(b.Facts, facts.Fact{
			FactID: fmt.Sprintf("fact-proc-%d-%d", idx, j),
			Kind: facts.FactProcess, Subject: ProcKey(node, bootID, p),
			Status: status, Source: "linux.proc_scan", Attributes: attrs,
		})
		procReceipt.RowCount++
		if p.Exe != "" {
			collectFilePerms(b, fmt.Sprintf("fact-exefile-%d-%d", idx, j), p.Exe, "linux.proc_scan")
		}
	}
	procReceipt.Finished = time.Now().UTC().Truncate(time.Second)
	procReceipt.DurationMs = procReceipt.Finished.Sub(procReceipt.Started).Milliseconds()
	addReceipt(procReceipt)
	if procReceipt.Status == "partial" {
		*execStatus = facts.ExecutionPartial
	}
}

// collectFilePerms 检查路径及其父目录（向上 3 层）的模式/属主/可写性。
func collectFilePerms(b *facts.FactBundle, factID, path, source string) {
	if path == "" {
		return
	}
	rStart := time.Now()
	receipt := facts.Receipt{
		TemplateID: "linux.file_perm", TemplateVersion: "1",
		Started: rStart.UTC().Truncate(time.Second),
		Status: "ok", Visibility: "full",
	}
	checked := 0
	cur := path
	for depth := 0; depth < 4 && cur != "" && cur != "/"; depth++ {
		fi, err := os.Lstat(cur)
		if err != nil {
			b.Facts = append(b.Facts, facts.Fact{
				FactID: fmt.Sprintf("%s-d%d", factID, depth),
				Kind: facts.FactFilePerm, Subject: cur,
				Status: facts.StatusPermissionDenied, Source: source,
				Attributes: map[string]string{"error": err.Error()},
			})
			receipt.Status = "partial"
			break
		}
		mode := fi.Mode()
		attrs := map[string]string{
			"path": cur,
			"mode": fmt.Sprintf("%#o", mode.Perm()),
			"dir":  fmt.Sprintf("%v", fi.IsDir()),
		}
		// 属主信息（Unix 平台）
		if st, ok := fileOwner(fi); ok {
			attrs["uid"] = fmt.Sprintf("%d", st.uid)
			attrs["gid"] = fmt.Sprintf("%d", st.gid)
		}
		// 低权主体可写判断：other 写或 group 写即记录（由规则按基线判定风险）
		if mode.Perm()&0o002 != 0 {
			attrs["writable_by_other"] = "true"
		}
		if mode.Perm()&0o020 != 0 {
			attrs["writable_by_group"] = "true"
		}
		b.Facts = append(b.Facts, facts.Fact{
			FactID: fmt.Sprintf("%s-d%d", factID, depth),
			Kind: facts.FactFilePerm, Subject: cur,
			Status: facts.StatusObserved, Source: source, Attributes: attrs,
		})
		checked++
		// 向上一层
		parent := dirOf(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	receipt.RowCount = checked
	receipt.Finished = time.Now().UTC().Truncate(time.Second)
	receipt.DurationMs = receipt.Finished.Sub(receipt.Started).Milliseconds()
	b.Receipts = append(b.Receipts, receipt)
}
