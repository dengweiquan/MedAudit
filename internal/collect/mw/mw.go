// Package mw 中间件采集器（M7-1：Tomcat / Nginx）。
//
// 与 OS 采集器同模型：在中间件所在主机上只读解析本地配置、部署目录与文件权限，
// 并结合 /proc 观察实际运行身份，产出标准事实包。不发网络请求、不改任何配置。
// 纪律：控制台账号只记账号与角色，口令及其哈希一律不采集。
package mw

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"medaudit/internal/facts"
)

// AdapterVersion 适配器版本（随里程碑走）。
const AdapterVersion = "0.8.0-m8"

// Options 采集参数。
type Options struct {
	Home       string // Tomcat: CATALINA_HOME；Nginx: 配置目录（含 nginx.conf）或 nginx.conf 文件路径
	HospitalID string
	AssetID    string
	PlanID     string
}

// builder 事实包组装器（收据/序号/完整性统一处理）。
type builder struct {
	facts    []facts.Fact
	receipts []facts.Receipt
	seq      int
	partial  bool
}

func (b *builder) fact(kind facts.FactKind, subject, source string, status facts.FieldStatus, attrs map[string]string) {
	b.seq++
	b.facts = append(b.facts, facts.Fact{
		FactID:  fmt.Sprintf("mw-fact-%06d", b.seq),
		Kind:    kind,
		Subject: subject,
		Status:  status,
		Source:  source,
		Attributes: attrs,
	})
}

func (b *builder) receipt(id string, status string, rows int) {
	now := time.Now().UTC().Truncate(time.Second)
	b.receipts = append(b.receipts, facts.Receipt{
		TemplateID:      id,
		TemplateVersion: "1",
		Started:         now,
		Finished:        now,
		Status:          status,
		RowCount:        rows,
		Visibility:      "full",
	})
	if status != "ok" {
		b.partial = true
	}
}

func (b *builder) execution() facts.ExecutionStatus {
	if b.partial {
		return facts.ExecutionPartial
	}
	return facts.ExecutionComplete
}

// newBundle 组装事实包骨架。
func newBundle(opts Options, target facts.TargetType, prefix, targetIdentity, targetVersion string, started time.Time, bd *builder) *facts.FactBundle {
	collector := "unknown@collector"
	if u, err := user.Current(); err == nil && u.Username != "" {
		collector = u.Username + "@collector"
	}
	return &facts.FactBundle{
		SchemaVersion: facts.SchemaVersion,
		BundleID:      "bundle-" + prefix + "-" + started.Format("20060102-150405"),
		PlanID:        opts.PlanID,
		Collector: facts.CollectorInfo{
			Name:           "medaudit-collector",
			Version:        AdapterVersion,
			Adapter:        target,
			AdapterVersion: AdapterVersion,
		},
		CollectedAt: facts.TimeRange{Started: started, Finished: time.Now().UTC().Truncate(time.Second)},
		Scope: facts.Scope{
			HospitalID:    opts.HospitalID,
			AssetID:       opts.AssetID,
			TargetType:    target,
			TargetVersion: targetVersion,
			Instance:      opts.Home,
		},
		Identities: facts.Identities{
			CollectorIdentity: collector,
			TargetIdentity:    targetIdentity,
			AppIdentitySource: "process_map",
		},
		Facts:     bd.facts,
		Receipts:  bd.receipts,
		Execution: bd.execution(),
	}
}

// procInfo 进程观察结果。
type procInfo struct {
	PID     int
	UID     int
	User    string
	Cmdline string
}

// findProcesses 扫描 /proc，返回 cmdline 命中 match 的进程（非 Linux 返回空）。
func findProcesses(match func(cmdline string) bool) []procInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []procInfo
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		cmd := strings.ReplaceAll(strings.TrimRight(string(raw), "\x00"), "\x00", " ")
		if !match(cmd) {
			continue
		}
		uid := -1
		if st, err := os.ReadFile(filepath.Join("/proc", e.Name(), "status")); err == nil {
			for _, line := range strings.Split(string(st), "\n") {
				if strings.HasPrefix(line, "Uid:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						uid, _ = strconv.Atoi(fields[1])
					}
					break
				}
			}
		}
		name := ""
		if uid >= 0 {
			if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
				name = u.Username
			} else {
				name = strconv.Itoa(uid)
			}
		}
		out = append(out, procInfo{PID: pid, UID: uid, User: name, Cmdline: cmd})
	}
	return out
}

// permAttrs 文件/目录权限属性（mode/owner/组与他人可写）。
func permAttrs(path string) map[string]string {
	info, err := os.Stat(path)
	if err != nil {
		return map[string]string{"error": "stat_failed"}
	}
	mode := info.Mode().Perm()
	attrs := map[string]string{
		"mode":              fmt.Sprintf("%04o", mode),
		"writable_by_group": boolStr(mode&0o020 != 0),
		"writable_by_other": boolStr(mode&0o002 != 0),
	}
	if uid, ok := statUID(info); ok {
		attrs["uid"] = strconv.Itoa(uid)
		if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
			attrs["owner"] = u.Username
		}
	}
	if gid, ok := statGID(info); ok {
		attrs["gid"] = strconv.Itoa(gid)
		if g, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
			attrs["group"] = g.Name
		}
	}
	return attrs
}

func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// loopback 判断监听地址是否仅回环。
func isLoopbackAddr(addr string) bool {
	switch addr {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}
