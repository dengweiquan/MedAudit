// Package linux 提供 Linux/systemd OS 事实采集。
// 只读 /proc 与 systemctl 白名单属性；禁止采集环境变量、完整命令行、
// 密码/哈希；禁止 sh -c。
package linux

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ProcInfo 从 /proc 解析的进程身份信息。
type ProcInfo struct {
	PID       int
	Comm      string // stat 中的进程名（截断 15 字符），不是完整命令行
	State     string
	PPID      int
	StartTime uint64 // stat field 22，时钟滴答数
	EUID      int    // 有效 UID
	EGID      int    // 有效 GID
	CapEff    uint64 // 有效能力位图
	Exe       string // /proc/PID/exe 目标（不可读则为空）
}

// BootID 读取 /proc/sys/kernel/random/boot_id。
func BootID() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// ReadProc 解析 /proc/PID/stat 与 /proc/PID/status。
// 正确处理 comm 中带括号的情况：取第一个 '(' 与最后一个 ')' 之间为 comm。
func ReadProc(pid int) (*ProcInfo, error) {
	p := &ProcInfo{PID: pid}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return nil, err
	}
	s := string(stat)
	l := strings.IndexByte(s, '(')
	r := strings.LastIndexByte(s, ')')
	if l < 0 || r < 0 || r <= l {
		return nil, fmt.Errorf("无法解析 /proc/%d/stat", pid)
	}
	p.Comm = s[l+1 : r]
	rest := strings.Fields(s[r+2:]) // 逗号后从 field 3 开始
	if len(rest) < 20 {
		return nil, fmt.Errorf("/proc/%d/stat 字段不足", pid)
	}
	p.State = rest[0]
	p.PPID, _ = strconv.Atoi(rest[1])
	// starttime 为原 field 22 → rest 索引 19
	p.StartTime, _ = strconv.ParseUint(rest[19], 10, 64)

	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			flds := strings.Fields(line[4:])
			if len(flds) >= 2 {
				p.EUID, _ = strconv.Atoi(flds[1])
			}
		} else if strings.HasPrefix(line, "Gid:") {
			flds := strings.Fields(line[4:])
			if len(flds) >= 2 {
				p.EGID, _ = strconv.Atoi(flds[1])
			}
		} else if strings.HasPrefix(line, "CapEff:") {
			p.CapEff, _ = strconv.ParseUint(strings.TrimSpace(line[7:]), 16, 64)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		p.Exe = exe
	}
	return p, nil
}

// ProcKey 进程稳定键：节点 + boot_id + PID + starttime。
func ProcKey(node, bootID string, p *ProcInfo) string {
	return fmt.Sprintf("%s/%s/%d/%d", node, bootID, p.PID, p.StartTime)
}

// capNames Linux capabilities 名称表（bit → 名）。
var capNames = []string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
	"CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
	"CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_ADMIN", "CAP_NET_RAW",
	"CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO",
	"CAP_SYS_CHROOT", "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN",
	"CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE", "CAP_SYS_TIME",
	"CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE",
	"CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN",
	"CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ",
}

// DecodeCaps 将 CapEff 位图译为能力名列表。
func DecodeCaps(eff uint64) []string {
	var out []string
	for i, n := range capNames {
		if eff&(1<<uint(i)) != 0 {
			out = append(out, n)
		}
	}
	return out
}

// IsFullRoot 判断是否为完整 root 能力集（参考：非 root 但高能力不能简单判通过）。
func IsFullRoot(eff uint64) bool {
	const full uint64 = 0x1ffffffffff // 41 个能力的全集（4.15+ 内核）
	return eff&full == full
}
