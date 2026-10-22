// Package oshpux HP-UX 权限事实采集（M21）。
//
// Go 无 HP-UX 目标平台，推送二进制不可行；本包以 SSH 远程命令集
// （或等价的命令转录）为采集通道：命令全部固定只读，本地按模板
// 解析为标准事实包。Runner 抽象命令执行：SSHRunner 走真实目标机，
// MapRunner 读转录映射（夹具/离线回放），两者共用同一解析路径。
package oshpux

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"medaudit/internal/facts"
)

// Runner 按命令键执行一条固定只读命令，返回标准输出。
// err 非空表示该命令不可用（文件不存在等），out 可同时有内容。
type Runner interface {
	Run(key string) (out string, err error)
}

// MapRunner 转录回放：key → 命令输出（缺失键视为命令失败）。
type MapRunner map[string]string

func (m MapRunner) Run(key string) (string, error) {
	if v, ok := m[key]; ok {
		return v, nil
	}
	return "", fmt.Errorf("转录缺失: %s", key)
}

// Commands 命令键 → 目标机命令（固定字符串，无外部输入拼接）。
var Commands = map[string]string{
	"uname":      "uname -a",
	"passwd":     "cat /etc/passwd",
	"group":      "cat /etc/group",
	"logins":     "logins -ox",
	"swlist":     "swlist -l bundle | head -60",
	"storeprobe": "ls -ld /etc/shadow /tcb /tcb/files/auth",
	"security":   "cat /etc/default/security",
	"kctune":     "kctune executable_stack",
	"sudoers":    "cat /etc/sudoers; cat /etc/sudoers.d/*",
	"rbac":       "ls /etc/rbac",
	"inetdconf":  "cat /etc/inetd.conf",
	"startupls":  "ls -ld /etc/inetd.conf /sbin/init.d /sbin/init.d/* /etc/rc.config.d /etc/rc.config.d/*",
	"setuidls":   "find /usr /sbin /opt -xdev -type f \\( -perm -4000 -o -perm -2000 \\) -exec ls -ld {} +",
}

// Config 采集配置。
type Config struct {
	HospitalID string
	AssetID    string
	PlanID     string
	// CollectorIdentity 采集者身份（如 ssh:user@host 或 transcript）。
	CollectorIdentity string
	CollectorVersion  string
}

// Collect 执行全部模板并组装事实包。单个模板失败记收据 failed 并使
// 执行结论 PARTIAL（不中断其余模板），与平台诚实口径一致。
func Collect(run Runner, cfg Config) (*facts.FactBundle, error) {
	now := time.Now().UTC().Truncate(time.Second)
	get := func(key string) (string, error) { return run.Run(key) }

	unameOut, _ := get("uname")
	node := nodeName(unameOut)

	b := &facts.FactBundle{
		SchemaVersion: facts.SchemaVersion,
		BundleID:      "bundle-os-hpux-" + now.Format("20060102-150405"),
		PlanID:        cfg.PlanID,
		Collector: facts.CollectorInfo{
			Name: "medaudit-collector", Version: cfg.CollectorVersion,
			Adapter: facts.TargetOSHpux, AdapterVersion: "1.0.0-m21",
		},
		CollectedAt: facts.TimeRange{Started: now},
		Scope: facts.Scope{
			HospitalID: cfg.HospitalID, AssetID: cfg.AssetID,
			TargetType: facts.TargetOSHpux, Profile: "m21-hpux-ssh",
		},
		Identities: facts.Identities{
			CollectorIdentity: cfg.CollectorIdentity,
			TargetIdentity:    "host:" + node,
			AppIdentitySource: "unknown",
		},
	}
	if b.PlanID == "" {
		b.PlanID = "plan-m21-hpux"
	}
	if b.Identities.CollectorIdentity == "" {
		b.Identities.CollectorIdentity = "transcript"
	}

	execStatus := facts.ExecutionComplete
	seq := 0
	nextID := func(prefix string) string {
		seq++
		return fmt.Sprintf("hpux-fact-%s-%03d", prefix, seq)
	}
	addReceipt := func(tid, status string, rows int, stage string) {
		b.Receipts = append(b.Receipts, facts.Receipt{
			TemplateID: tid, TemplateVersion: "1",
			Started: now, Finished: time.Now().UTC().Truncate(time.Second),
			Status: status, Visibility: "full", RowCount: rows, ErrorStage: stage,
		})
		if status != "ok" {
			execStatus = facts.ExecutionPartial
		}
	}

	collectIdentity(b, get, nextID, addReceipt)
	collectAuthPolicy(b, get, nextID, addReceipt)
	collectSudoRbac(b, get, nextID, addReceipt)
	collectInetd(b, get, nextID, addReceipt)
	collectStartupPerm(b, get, nextID, addReceipt)
	collectSetuid(b, get, nextID, addReceipt)

	b.Execution = execStatus
	b.CollectedAt.Finished = time.Now().UTC().Truncate(time.Second)
	return b, nil
}

func nodeName(unameOut string) string {
	f := splitFields(unameOut)
	if len(f) >= 2 {
		return f[1]
	}
	return "unknown"
}

func splitFields(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// ZipBytes 把事实包序列化为 bundle zip 字节（与 facts.WriteZip 同构）。
func ZipBytes(b *facts.FactBundle) ([]byte, error) {
	data, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("bundle.json")
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SortedKeys 返回命令键的稳定排序（调试/文档用）。
func SortedKeys() []string {
	keys := make([]string, 0, len(Commands))
	for k := range Commands {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
