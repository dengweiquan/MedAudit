//go:build windows

package windows

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// processTokenUser 读取进程令牌中的实际运行身份（DOMAIN\user）。
// 进程已退出或无权查询时返回错误，由调用方记为 permission_denied，不填默认值。
func processTokenUser(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)

	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return "", fmt.Errorf("OpenProcessToken(%d): %w", pid, err)
	}
	defer tok.Close()

	var needed uint32
	_ = windows.GetTokenInformation(tok, windows.TokenUser, nil, 0, &needed)
	if needed == 0 {
		return "", fmt.Errorf("GetTokenInformation(%d): 无法获取长度", pid)
	}
	buf := make([]byte, needed)
	if err := windows.GetTokenInformation(tok, windows.TokenUser, &buf[0], needed, &needed); err != nil {
		return "", fmt.Errorf("GetTokenInformation(%d): %w", pid, err)
	}
	tu := (*windows.Tokenuser)(unsafe.Pointer(&buf[0]))
	account, domain, _, err := tu.User.Sid.LookupAccount("")
	if err != nil {
		// SID 解析失败时退回 SID 字符串，保证身份可追溯
		return tu.User.Sid.String(), nil
	}
	if domain != "" {
		return domain + `\` + account, nil
	}
	return account, nil
}

// currentUser 返回采集器进程自身的身份（DOMAIN\user）。
func currentUser() string {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return "unknown"
	}
	defer tok.Close()
	var needed uint32
	_ = windows.GetTokenInformation(tok, windows.TokenUser, nil, 0, &needed)
	buf := make([]byte, needed)
	if err := windows.GetTokenInformation(tok, windows.TokenUser, &buf[0], needed, &needed); err != nil {
		return "unknown"
	}
	tu := (*windows.Tokenuser)(unsafe.Pointer(&buf[0]))
	account, domain, _, err := tu.User.Sid.LookupAccount("")
	if err != nil {
		return tu.User.Sid.String()
	}
	if domain != "" {
		return domain + `\` + account
	}
	return account
}
