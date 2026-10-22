//go:build windows

package windows

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	netapi32                 = windows.NewLazySystemDLL("netapi32.dll")
	procNetLocalGroupEnum    = netapi32.NewProc("NetLocalGroupEnum")
	procNetLocalGroupMembers = netapi32.NewProc("NetLocalGroupGetMembers")
	procNetApiBufferFree     = netapi32.NewProc("NetApiBufferFree")
)

const maxPreferredLength = ^uint32(0) // MAX_PREFERRED_LENGTH

type localGroupInfo1 struct {
	Name    *uint16
	Comment *uint16
}

type localGroupMembersInfo2 struct {
	Sid           *windows.SID
	SidUsage      uint32
	DomainAndName *uint16
}

// enumLocalGroups 枚举本地组名（level 1）。
func enumLocalGroups() ([]string, error) {
	var bufptr *byte
	var entriesRead, totalEntries uint32
	r1, _, e1 := procNetLocalGroupEnum.Call(
		0, // servername = NULL（本地）
		1, // level
		uintptr(unsafe.Pointer(&bufptr)),
		uintptr(maxPreferredLength),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		0, // resume_handle = NULL
	)
	if bufptr != nil {
		defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(bufptr)))
	}
	if r1 != 0 {
		return nil, fmt.Errorf("NetLocalGroupEnum: %v", e1)
	}
	if entriesRead == 0 || bufptr == nil {
		return []string{}, nil
	}
	raw := (*[1 << 20]localGroupInfo1)(unsafe.Pointer(bufptr))[:entriesRead:entriesRead]
	out := make([]string, 0, entriesRead)
	for _, g := range raw {
		out = append(out, windows.UTF16PtrToString(g.Name))
	}
	return out, nil
}

// localGroupMembers 取本地组成员（level 2，返回 DOMAIN\name 形式）。
func localGroupMembers(group string) ([]string, error) {
	namePtr, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return nil, err
	}
	var bufptr *byte
	var entriesRead, totalEntries uint32
	r1, _, e1 := procNetLocalGroupMembers.Call(
		0, // servername = NULL
		uintptr(unsafe.Pointer(namePtr)),
		2, // level
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
		return nil, fmt.Errorf("NetLocalGroupGetMembers(%s): %v", group, e1)
	}
	if entriesRead == 0 || bufptr == nil {
		return []string{}, nil
	}
	raw := (*[1 << 20]localGroupMembersInfo2)(unsafe.Pointer(bufptr))[:entriesRead:entriesRead]
	out := make([]string, 0, entriesRead)
	for _, m := range raw {
		out = append(out, windows.UTF16PtrToString(m.DomainAndName))
	}
	return out, nil
}
