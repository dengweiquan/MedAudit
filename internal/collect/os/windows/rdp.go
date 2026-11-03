//go:build windows

package windows

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

const (
	rdpPolicyPath = `SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`
	rdpLocalPath  = `SYSTEM\CurrentControlSet\Control\Terminal Server`
	rdpTcpPath    = `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
)

// readRegDWORD 读 DWORD 值：键/值不存在 → Present=false（不报错，不得默认为安全）；
// 其他错误（如拒绝访问）→ 返回 error，由调用方记收据失败。
func readRegDWORD(path, name string) (RDPValue, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return RDPValue{}, nil
		}
		return RDPValue{}, err
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return RDPValue{}, nil
		}
		return RDPValue{}, err
	}
	return RDPValue{Value: v != 0, Present: true}, nil
}

// readRDPSettings 读 RDP 有效配置：组策略优先于本地；回退语义见 ResolveRDPSettingsRaw
// （组策略被拒时返回错误，不回退本地）。
// fDenyTSConnections=0 表示允许连接（值取反后为 enabled）；UserAuthentication=1 表示要求 NLA。
func readRDPSettings() (RDPSettings, error) {
	read := func(path, name string) RegRead {
		v, err := readRegDWORD(path, name)
		return RegRead{Value: v, Err: err}
	}
	return ResolveRDPSettingsRaw(
		read(rdpPolicyPath, "fDenyTSConnections"),
		read(rdpLocalPath, "fDenyTSConnections"),
		read(rdpPolicyPath, "UserAuthentication"),
		read(rdpTcpPath, "UserAuthentication"),
	)
}
