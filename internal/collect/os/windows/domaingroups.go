//go:build windows

package windows

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procNetGroupEnum     = netapi32.NewProc("NetGroupEnum")
	procNetGroupGetUsers = netapi32.NewProc("NetGroupGetUsers")
	procNetGetDCName     = netapi32.NewProc("NetGetDCName")
)

type groupInfo0 struct {
	Name *uint16
}

type groupUsersInfo0 struct {
	Name *uint16
}

// domainControllerName 返回本机所在域的 DC 名称（含 \\ 前缀，如 \\WIN-DC1）。
// 未加入域时返回空字符串（常态，不视为错误）。
func domainControllerName() string {
	var bufptr *byte
	r1, _, _ := procNetGetDCName.Call(
		0, // servername = NULL
		0, // domainname = NULL（本机账户域）
		uintptr(unsafe.Pointer(&bufptr)),
	)
	if bufptr != nil {
		defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(bufptr)))
	}
	if r1 != 0 || bufptr == nil {
		return ""
	}
	// NetGetDCName 分配的缓冲区内直接存放以 NUL 结尾的 DC 名字符串
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(bufptr)))
}

// enumDomainGroups 枚举域全局组（level 0）。server 为 DC 名（含 \\ 前缀）。
func enumDomainGroups(server string) ([]string, error) {
	srvPtr, err := windows.UTF16PtrFromString(server)
	if err != nil {
		return nil, err
	}
	var bufptr *byte
	var entriesRead, totalEntries uint32
	r1, _, e1 := procNetGroupEnum.Call(
		uintptr(unsafe.Pointer(srvPtr)),
		0, // level: GROUP_INFO_0
		uintptr(unsafe.Pointer(&bufptr)),
		uintptr(maxPreferredLength),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		0,
	)
	if bufptr != nil {
		defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(bufptr)))
	}
	if r1 != 0 {
		return nil, fmt.Errorf("NetGroupEnum: %v", e1)
	}
	if entriesRead == 0 || bufptr == nil {
		return []string{}, nil
	}
	raw := (*[1 << 20]groupInfo0)(unsafe.Pointer(bufptr))[:entriesRead:entriesRead]
	out := make([]string, 0, entriesRead)
	for _, g := range raw {
		out = append(out, windows.UTF16PtrToString(g.Name))
	}
	return out, nil
}

// domainGroupMembers 取域全局组成员（level 0，返回纯名称：用户或嵌套全局组）。
func domainGroupMembers(server, group string) ([]string, error) {
	srvPtr, err := windows.UTF16PtrFromString(server)
	if err != nil {
		return nil, err
	}
	grpPtr, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return nil, err
	}
	var bufptr *byte
	var entriesRead, totalEntries uint32
	r1, _, e1 := procNetGroupGetUsers.Call(
		uintptr(unsafe.Pointer(srvPtr)),
		uintptr(unsafe.Pointer(grpPtr)),
		0, // level: GROUP_USERS_INFO_0
		uintptr(unsafe.Pointer(&bufptr)),
		uintptr(maxPreferredLength),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		0,
	)
	if bufptr != nil {
		defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(bufptr)))
	}
	if r1 != 0 {
		return nil, fmt.Errorf("NetGroupGetUsers(%s): %v", group, e1)
	}
	if entriesRead == 0 || bufptr == nil {
		return []string{}, nil
	}
	raw := (*[1 << 20]groupUsersInfo0)(unsafe.Pointer(bufptr))[:entriesRead:entriesRead]
	out := make([]string, 0, entriesRead)
	for _, m := range raw {
		out = append(out, windows.UTF16PtrToString(m.Name))
	}
	return out, nil
}

// dcShortName 去掉 DC 名的 \\ 前缀，仅用于事实标注。
func dcShortName(server string) string {
	return strings.TrimPrefix(server, "\\\\")
}
