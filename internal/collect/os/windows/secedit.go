//go:build windows

package windows

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// exportSecedit 只读导出本地安全策略：secedit /export /cfg <临时文件> /quiet。
// 不修改任何策略；临时文件用后删除。失败时返回 error（复杂度规则随之 UNKNOWN）。
// 注意：secedit 通常需要管理员权限；非管理员运行时导出失败是预期行为，不是数据问题。
func exportSecedit() ([]byte, error) {
	f, err := os.CreateTemp("", "medaudit-secedit-*.inf")
	if err != nil {
		return nil, err
	}
	name := f.Name()
	f.Close()
	defer os.Remove(name)
	cmd := exec.Command("secedit", "/export", "/cfg", name, "/quiet")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("secedit /export: %w（输出：%s）", err, truncSeceditOut(string(out)))
	}
	return os.ReadFile(name)
}

func truncSeceditOut(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 500 {
		return s[:500] + "…"
	}
	return s
}
