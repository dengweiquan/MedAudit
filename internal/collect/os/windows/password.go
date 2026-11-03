//go:build windows

package windows

import (
	"fmt"
	"unsafe"
)

var (
	procNetUserModalsGet = netapi32.NewProc("NetUserModalsGet")
	procNetServerGetInfo = netapi32.NewProc("NetServerGetInfo")
	procNetGetJoinInfo   = netapi32.NewProc("NetGetJoinInformation")
)

// USER_MODALS_INFO_0/3 按 MSDN 字段顺序；全部为 DWORD，时间单位为秒。
type userModalsInfo0 struct {
	MinPasswdLen    uint32
	MaxPasswdAge    uint32
	MinPasswdAge    uint32
	ForceLogoff     uint32
	PasswordHistLen uint32
}

type userModalsInfo3 struct {
	LockoutDuration          uint32
	LockoutObservationWindow uint32
	LockoutThreshold         uint32
}

type serverInfo101 struct {
	PlatformID   uint32
	Name         *uint16
	VersionMajor uint32
	VersionMinor uint32
	Type         uint32
	Comment      *uint16
}

const svTypeDomainCtrl = 0x00000008

// queryPasswordPolicy 调 NetUserModalsGet（level 0 取长度/最长使用期，level 3 取锁定阈值等，
// servername=NULL 即本机）。覆盖范围由机器角色标注，见 machinePasswordScope。
func queryPasswordPolicy() (PasswordPolicy, error) {
	var p PasswordPolicy
	var bufptr *byte
	r1, _, e1 := procNetUserModalsGet.Call(0, 0, uintptr(unsafe.Pointer(&bufptr)))
	if r1 != 0 {
		return p, fmt.Errorf("NetUserModalsGet level 0: %v", e1)
	}
	if bufptr != nil {
		defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(bufptr)))
		info := (*userModalsInfo0)(unsafe.Pointer(bufptr))
		p.MinLength = info.MinPasswdLen
		p.MaxAgeSec = info.MaxPasswdAge
		p.MinAgeSec = info.MinPasswdAge
		p.ForceLogoffSec = info.ForceLogoff
		p.HistLen = info.PasswordHistLen
	}
	var bufptr3 *byte
	r1, _, e1 = procNetUserModalsGet.Call(0, 3, uintptr(unsafe.Pointer(&bufptr3)))
	if r1 != 0 {
		return p, fmt.Errorf("NetUserModalsGet level 3: %v", e1)
	}
	if bufptr3 != nil {
		defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(bufptr3)))
		info := (*userModalsInfo3)(unsafe.Pointer(bufptr3))
		p.LockoutDurationSec = info.LockoutDuration
		p.LockoutWindowSec = info.LockoutObservationWindow
		p.LockoutThreshold = info.LockoutThreshold
	}
	role := machineRole()
	p.Role = role
	p.Scope = passwordScopeForRole(role)
	return p, nil
}

// machineRole 探测本机角色（工作组 / 域成员 / 域控），三态分别验证实际查询对象：
//   - NetGetJoinInformation 得加入状态（Workgroup/Domain）；
//   - 域加入状态下再以 NetServerGetInfo 的 SV_TYPE_DOMAIN_CTRL 区分域控与普通域成员；
//   - 域控的 NetUserModalsGet 返回域默认策略；工作组与域成员均返回本地 SAM 策略——
//     域成员本机的查询不等于域账号默认策略，域账号默认策略不在本 API 覆盖内；
//   - 探测失败时返回 unknown（值仍可用，不猜测覆盖范围）。
//
// 细粒度用户策略（FGPP/PSO）不在本 API 覆盖内。
func machineRole() string {
	var nameBuf *uint16
	var joinStatus uint32
	r1, _, _ := procNetGetJoinInfo.Call(0, uintptr(unsafe.Pointer(&nameBuf)), uintptr(unsafe.Pointer(&joinStatus)))
	if nameBuf != nil {
		defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(nameBuf)))
	}
	// NetSetupJoinStatus：0 未知，1 工作组，2 域。
	isDC := false
	var bufptr *byte
	if r1, _, _ := procNetServerGetInfo.Call(0, 101, uintptr(unsafe.Pointer(&bufptr))); r1 == 0 && bufptr != nil {
		defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(bufptr)))
		isDC = (*serverInfo101)(unsafe.Pointer(bufptr)).Type&svTypeDomainCtrl != 0
	}
	if isDC {
		return "domain-controller"
	}
	if r1 != 0 {
		return "unknown"
	}
	switch joinStatus {
	case 1:
		return "workgroup"
	case 2:
		return "domain-member"
	default:
		return "unknown"
	}
}

// machinePasswordScope 由机器角色定覆盖范围（见 passwordScopeForRole）。
func machinePasswordScope() string {
	return passwordScopeForRole(machineRole())
}
