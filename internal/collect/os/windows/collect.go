//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"medaudit/internal/facts"
)

// partialError 部分采集失败：已产出部分事实，但有项目未能读取，
// 收据应记 partial（而非 ok 或 denied），使规则门控走 Partial 语义：
// 已有明确违规仍 FAIL，无命中则 UNKNOWN，绝不误判 PASS。
type partialError struct{ msg string }

func (e *partialError) Error() string { return e.msg }

// Config 采集配置。
type Config struct {
	HospitalID       string
	AssetID          string
	PlanID           string
	Services         []string // 为空时采集全部 Win32 服务
	CollectorVersion string
}

var (
	ntdll             = windows.NewLazySystemDLL("ntdll.dll")
	procRtlGetVersion = ntdll.NewProc("RtlGetVersion")
)

type rtlOSVersionInfo struct {
	OSVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformID        uint32
	CSDVersion        [128]uint16
}

// osVersion 返回 "10.0.17763" 形式的版本。
func osVersion() string {
	var vi rtlOSVersionInfo
	vi.OSVersionInfoSize = uint32(unsafe.Sizeof(vi))
	r1, _, _ := procRtlGetVersion.Call(uintptr(unsafe.Pointer(&vi)))
	if r1 != 0 {
		return "unknown"
	}
	return fmt.Sprintf("%d.%d.%d", vi.MajorVersion, vi.MinorVersion, vi.BuildNumber)
}

// Collect 执行 Windows 只读采集，返回事实包。
func Collect(ctx context.Context, cfg Config) (*facts.FactBundle, error) {
	started := time.Now().UTC()
	hostname, _ := os.Hostname()
	b := &facts.FactBundle{
		SchemaVersion: facts.SchemaVersion,
		BundleID:      fmt.Sprintf("bundle-win-%s", started.Format("20060102-150405")),
		PlanID:        cfg.PlanID,
		Collector: facts.CollectorInfo{
			Name: "medaudit-collector", Version: cfg.CollectorVersion,
			Adapter: facts.TargetOSWindows, AdapterVersion: "1",
		},
		CollectedAt: facts.TimeRange{Started: started},
		Scope: facts.Scope{
			HospitalID: cfg.HospitalID, AssetID: cfg.AssetID,
			TargetType: facts.TargetOSWindows, TargetVersion: osVersion(),
			Instance: hostname,
		},
		Identities: facts.Identities{
			CollectorIdentity: currentUser() + "@collector",
			TargetIdentity:    hostname,
		},
	}
	if b.Identities.CollectorIdentity == b.Identities.TargetIdentity+"@collector" {
		// 恒为真检查占位：身份三元组由 Validate 兜底
	}

	addReceipt := func(id, ver string, fn func() (int, error)) {
		rs := time.Now()
		rows, err := fn()
		rf := time.Now()
		status := "ok"
		errStage := ""
		if err != nil {
			var pe *partialError
			if errors.As(err, &pe) {
				status = "partial"
			} else {
				status = "denied"
			}
			errStage = facts.RedactSecrets(err.Error())
		}
		b.Receipts = append(b.Receipts, facts.Receipt{
			TemplateID: id, TemplateVersion: ver,
			Started: rs, Finished: rf, DurationMs: rf.Sub(rs).Milliseconds(),
			RowCount: rows, Status: status, ErrorStage: errStage,
		})
	}

	// 1) 服务枚举 + 配置
	var services []ServiceInfo
	addReceipt("win.svc_enum", "1", func() (int, error) {
		svcs, err := enumServices()
		if err != nil {
			return 0, err
		}
		if len(cfg.Services) > 0 {
			want := map[string]bool{}
			for _, s := range cfg.Services {
				want[strings.ToLower(s)] = true
			}
			var filtered []ServiceInfo
			for _, s := range svcs {
				if want[strings.ToLower(s.Name)] {
					filtered = append(filtered, s)
				}
			}
			svcs = filtered
		}
		services = svcs
		return len(svcs), nil
	})

	factSeq := 0
	nextID := func(prefix string) string {
		factSeq++
		return fmt.Sprintf("win-fact-%s-%06d", prefix, factSeq)
	}

	// 2) 服务配置事实 + 运行中服务的进程令牌事实
	for _, s := range services {
		status := facts.StatusObserved
		attrs := map[string]string{
			"display_name":    s.DisplayName,
			"start_type":      startTypeName(s.StartType),
			"state":           serviceStateName(s.State),
			"binary_path":     s.BinaryPath,
			"service_account": s.ServiceAccount,
			"pid":             fmt.Sprint(s.PID),
		}
		if s.ConfigErr != nil {
			status = facts.StatusPermissionDenied
			attrs["config_error"] = s.ConfigErr.Error()
		}
		b.Facts = append(b.Facts, facts.Fact{
			FactID: nextID("svc"), Kind: facts.FactServiceConfig,
			Subject: s.Name, Status: status, Source: "win.svc_enum",
			Attributes: attrs,
		})

		if s.State == windows.SERVICE_RUNNING && s.PID != 0 {
			actualUser, terr := processTokenUser(s.PID)
			pattrs := map[string]string{
				"configured_user": s.ServiceAccount,
				"binary_path":     s.BinaryPath,
				"pid":             fmt.Sprint(s.PID),
			}
			pstatus := facts.StatusObserved
			if terr != nil {
				pstatus = facts.StatusPermissionDenied
				pattrs["token_error"] = terr.Error()
			} else {
				pattrs["actual_user"] = actualUser
			}
			b.Facts = append(b.Facts, facts.Fact{
				FactID: nextID("proc"), Kind: facts.FactProcess,
				Subject: s.Name, Status: pstatus, Source: "win.proc_token",
				Attributes: pattrs,
			})
		}

		// 3) 服务二进制与其父目录的 ACL 检查（最多向上 3 级）
		for _, p := range exeAndParents(s.BinaryPath, 3) {
			writable, summary, aerr := aclWritableByLowPriv(p)
			fstatus := facts.StatusObserved
			fattrs := map[string]string{
				"writable_by_low_priv": fmt.Sprint(writable),
			}
			if summary != "" {
				fattrs["ace_hits"] = summary
			}
			if aerr != nil {
				fstatus = facts.StatusPermissionDenied
				fattrs["acl_error"] = aerr.Error()
			}
			b.Facts = append(b.Facts, facts.Fact{
				FactID: nextID("acl"), Kind: facts.FactFilePerm,
				Subject: p, Status: fstatus, Source: "win.acl_check",
				Attributes: fattrs,
			})
		}
	}

	// 4) 本地组（重点：Administrators）成员 → role_edge
	addReceipt("win.group_enum", "1", func() (int, error) {
		groups, err := enumLocalGroups()
		if err != nil {
			return 0, err
		}
		n := 0
		for _, g := range groups {
			members, merr := localGroupMembers(g)
			if merr != nil {
				b.Facts = append(b.Facts, facts.Fact{
					FactID: nextID("grp"), Kind: facts.FactRoleEdge,
					Subject: g, Status: facts.StatusPermissionDenied,
					Source:     "win.group_enum",
					Attributes: map[string]string{"member_error": merr.Error()},
				})
				continue
			}
			for _, m := range members {
				b.Facts = append(b.Facts, facts.Fact{
					FactID: nextID("grp"), Kind: facts.FactRoleEdge,
					Subject: m, Status: facts.StatusObserved, Source: "win.group_enum",
					PermissionPath: []string{g, m},
					Attributes:     map[string]string{"group": g},
				})
				n++
			}
		}
		return n, nil
	})

	// 5) 域全局组（M8-2）：域控/域成员上经 NetGroup 枚举全局组及成员（含嵌套组）→ role_edge。
	//    未加域是常态：记 unsupported 事实，不算失败。
	addReceipt("win.domain_group_enum", "1", func() (int, error) {
		dc := domainControllerName()
		if dc == "" {
			b.Facts = append(b.Facts, facts.Fact{
				FactID: nextID("dom"), Kind: facts.FactIdentity,
				Subject: hostname, Status: facts.StatusUnsupported,
				Source:     "win.domain_group_enum",
				Attributes: map[string]string{"domain_joined": "false"},
			})
			return 0, nil
		}
		groups, err := enumDomainGroups(dc)
		if err != nil {
			return 0, err
		}
		n := 0
		for _, g := range groups {
			if n >= 5000 {
				break
			}
			members, merr := domainGroupMembers(dc, g)
			if merr != nil {
				b.Facts = append(b.Facts, facts.Fact{
					FactID: nextID("dom"), Kind: facts.FactRoleEdge,
					Subject: g, Status: facts.StatusPermissionDenied,
					Source:     "win.domain_group_enum",
					Attributes: map[string]string{"member_error": merr.Error()},
				})
				continue
			}
			for _, m := range members {
				b.Facts = append(b.Facts, facts.Fact{
					FactID: nextID("dom"), Kind: facts.FactRoleEdge,
					Subject: m, Status: facts.StatusObserved,
					Source:         "win.domain_group_enum",
					PermissionPath: []string{g, m},
					Attributes:     map[string]string{"group": g, "dc": dcShortName(dc)},
				})
				n++
			}
		}
		return n, nil
	})

	// 6) Windows 口令策略（NetUserModalsGet level 0/3）：本地 SAM 或域默认策略；
	//    细粒度用户策略（FGPP/PSO）不在本 API 覆盖内，事实 scope 标注覆盖范围。
	addReceipt("win.password_policy", "1", func() (int, error) {
		pol, err := queryPasswordPolicy()
		if err != nil {
			return 0, err
		}
		b.Facts = append(b.Facts, facts.Fact{
			FactID: nextID("pwd"), Kind: facts.FactAccountConfig,
			Subject: "password-policy", Status: facts.StatusObserved, Source: "win.password_policy",
			Attributes: PasswordPolicyAttributes(pol),
		})
		return 1, nil
	})

	// 7) secedit 复杂度（只读导出）：渠道不可用则无事实，复杂度规则 UNKNOWN；
	//    不解析本地化 net accounts 文案。
	addReceipt("win.secedit", "1", func() (int, error) {
		raw, err := exportSecedit()
		if err != nil {
			return 0, err
		}
		sec := ParseSeceditInf(raw)
		// secedit 与数值策略的适用范围必须一致：同一 machineRole 派生 scope，不各自探测。
		role := machineRole()
		attrs := map[string]string{"scope": passwordScopeForRole(role), "machine_role": role}
		if v, ok := sec["passwordcomplexity"]; ok {
			attrs["password_complexity"] = v
		}
		b.Facts = append(b.Facts, facts.Fact{
			FactID: nextID("sec"), Kind: facts.FactAccountConfig,
			Subject: "password-policy", Status: facts.StatusObserved, Source: "win.secedit",
			Attributes: attrs,
		})
		return 1, nil
	})

	// 8) RDP 有效配置（组策略优先于本地）：enabled 读不到则整段失败；
	//    NLA 缺失则事实无 nla 属性，NLA 规则 UNKNOWN（不默认为安全）。
	addReceipt("win.rdp", "1", func() (int, error) {
		s, err := readRDPSettings()
		if err != nil {
			return 0, err
		}
		if !s.Enabled.Present {
			return 0, fmt.Errorf("RDP 开关注册表值均不存在，无法判定")
		}
		b.Facts = append(b.Facts, facts.Fact{
			FactID: nextID("rdp"), Kind: facts.FactAccountConfig,
			Subject: "rdp", Status: facts.StatusObserved, Source: "win.rdp",
			Attributes: RDPAttributes(s),
		})
		return 1, nil
	})

	// 9) MSSQL ForceEncryption（本机注册表，逐实例）：值只证明“已配置”，
	//    重启后生效状态未验证（事实 effective=unknown）；单实例不可读不掩盖其他实例：
	//    有实例不可读时收据记 partial（门控 Partial：已有明确违规仍 FAIL，
	//    无命中则 UNKNOWN）；枚举跳过（实例名存在但 ID 读不到）同样 partial，
	//    绝不把枚举不全读成“无实例”。
	addReceipt("win.mssql_force_encryption", "1", func() (int, error) {
		insts, skipped, err := enumMSSQLInstances()
		if err != nil {
			return 0, err
		}
		if len(insts) == 0 && skipped == 0 {
			b.Facts = append(b.Facts, facts.Fact{
				FactID: nextID("ms"), Kind: facts.FactAccountConfig,
				Subject: "mssql-instances", Status: facts.StatusObserved, Source: "win.mssql_force_encryption",
				Attributes: map[string]string{"mssql_instances": "0"},
			})
			return 0, nil
		}
		n := 0
		failed := 0
		var firstErr error
		for _, inst := range insts {
			present, value, rerr := readForceEncryption(inst.ID)
			if rerr != nil {
				st := facts.StatusUnsupported
				if isRegistryDenied(rerr) {
					st = facts.StatusPermissionDenied
				}
				b.Facts = append(b.Facts, facts.Fact{
					FactID: nextID("ms"), Kind: facts.FactAccountConfig,
					Subject: inst.Name, Status: st, Source: "win.mssql_force_encryption",
					Attributes: map[string]string{
						"instance_id": inst.ID, "registry_path": MSSQLSuperSocketPath(inst.ID),
						"error": facts.RedactSecrets(rerr.Error()),
					},
				})
				failed++
				if firstErr == nil {
					firstErr = rerr
				}
				continue
			}
			b.Facts = append(b.Facts, facts.Fact{
				FactID: nextID("ms"), Kind: facts.FactAccountConfig,
				Subject: inst.Name, Status: facts.StatusObserved, Source: "win.mssql_force_encryption",
				Attributes: MSSQLForceEncryptionAttrs(inst, MSSQLSuperSocketPath(inst.ID), present, value),
			})
			n++
		}
		// 部分实例不可读（或枚举跳过）且已有可读实例：partial 收据。
		if (failed > 0 || skipped > 0) && n > 0 {
			return n, &partialError{msg: fmt.Sprintf(
				"部分实例 ForceEncryption 不可读（实例读取失败 %d 个，枚举跳过 %d 个），已读 %d 个",
				failed, skipped, n)}
		}
		// 全部不可读（含枚举到的实例名全部跳过）：无可读事实，记失败，不判无实例。
		if n == 0 {
			if firstErr != nil {
				return 0, firstErr
			}
			return 0, fmt.Errorf("枚举到实例名但实例 ID 全部读不到（跳过 %d 个），无法判定", skipped)
		}
		return n, nil
	})

	finished := time.Now().UTC()
	b.CollectedAt.Finished = finished
	b.Execution = facts.ExecutionComplete
	for _, r := range b.Receipts {
		if r.Status != "ok" {
			b.Execution = facts.ExecutionPartial
			break
		}
	}
	_ = ctx
	return b, nil
}

// exeAndParents 从服务二进制路径提取可执行文件及其父目录（最多 levels 级）。
func exeAndParents(binaryPath string, levels int) []string {
	exe := extractExe(binaryPath)
	if exe == "" {
		return nil
	}
	var out []string
	out = append(out, exe)
	dir := filepath.Dir(exe)
	for i := 0; i < levels && dir != "" && dir != "."; i++ {
		out = append(out, dir)
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return out
}

// extractExe 处理带引号/带参数的服务二进制路径。
func extractExe(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, `"`) {
		if end := strings.Index(p[1:], `"`); end >= 0 {
			return p[1 : 1+end]
		}
		return strings.Trim(p, `"`)
	}
	if i := strings.IndexAny(p, " \t"); i >= 0 {
		return p[:i]
	}
	return p
}
