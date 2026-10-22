//go:build windows

package windows

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32                 = windows.NewLazySystemDLL("advapi32.dll")
	procGetNamedSecurityInfo = advapi32.NewProc("GetNamedSecurityInfoW")
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procLocalFree            = kernel32.NewProc("LocalFree")
)

const (
	seFileObject            = 1
	daclSecurityInformation = 0x00000004
	accessAllowedAceType    = 0

	genericWrite   = 0x40000000
	fileWriteData  = 0x0002
	fileAppendData = 0x0004
	fileWriteEA    = 0x0010
	fileWriteAttr  = 0x0100
	deleteRight    = 0x00010000
	writeDac       = 0x00040000
	writeOwner     = 0x00080000
)

// 低权主体 SID：仅对这三类显式 ALLOW 写权限做保守判定。
// DENY ACE 与嵌套组成员不展开，判定为 false 时不代表"安全"，只代表"未发现显式低权写"。
var lowPrivSIDs = map[string]bool{
	"S-1-1-0":      true, // Everyone
	"S-1-5-32-545": true, // BUILTIN\Users
	"S-1-5-11":     true, // Authenticated Users
}

type aclHeader struct {
	AclRevision uint8
	Sbz1        uint8
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
}

type aceHeader struct {
	AceType  uint8
	AceFlags uint8
	AceSize  uint16
}

// aclWritableByLowPriv 检查路径 DACL 是否存在授予低权主体的显式写 ACE。
// 返回 (可写, 命中摘要, 错误)。查询失败返回错误，不猜测。
func aclWritableByLowPriv(path string) (bool, string, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, "", err
	}
	var sd *byte
	var dacl unsafe.Pointer
	r1, _, e1 := procGetNamedSecurityInfo.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(seFileObject),
		uintptr(daclSecurityInformation),
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&dacl)),
		uintptr(unsafe.Pointer(&sd)),
	)
	if sd != nil {
		defer procLocalFree.Call(uintptr(unsafe.Pointer(sd)))
	}
	if r1 != 0 {
		return false, "", fmt.Errorf("GetNamedSecurityInfo: %v", e1)
	}
	if dacl == nil {
		return false, "", fmt.Errorf("路径 %s 无 DACL（可能查询受限）", path)
	}
	hdr := (*aclHeader)(dacl)
	var hits []string
	acePtr := unsafe.Add(dacl, unsafe.Sizeof(aclHeader{}))
	for i := uint16(0); i < hdr.AceCount; i++ {
		ah := (*aceHeader)(acePtr)
		if ah.AceType == accessAllowedAceType && ah.AceSize >= 12 {
			mask := *(*uint32)(unsafe.Add(acePtr, 4))
			sid := (*windows.SID)(unsafe.Add(acePtr, 8))
			sidStr := sid.String()
			if lowPrivSIDs[sidStr] && maskHasWrite(mask) {
				hits = append(hits, fmt.Sprintf("%s mask=0x%x", sidStr, mask))
			}
		}
		if ah.AceSize == 0 {
			break // 损坏的 ACE 链，停止遍历
		}
		acePtr = unsafe.Add(acePtr, uintptr(ah.AceSize))
	}
	if len(hits) > 0 {
		return true, strings.Join(hits, "; "), nil
	}
	return false, "", nil
}

func maskHasWrite(mask uint32) bool {
	const writeBits = genericWrite | fileWriteData | fileAppendData |
		fileWriteEA | fileWriteAttr | deleteRight | writeDac | writeOwner
	return mask&writeBits != 0
}
