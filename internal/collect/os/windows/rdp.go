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

// readRDPSettings 读 RDP 有效配置：组策略优先于本地。
// fDenyTSConnections=0 表示允许连接（值取反后为 enabled）；UserAuthentication=1 表示要求 NLA。
func readRDPSettings() (RDPSettings, error) {
	var s RDPSettings
	polDeny, err := readRegDWORD(rdpPolicyPath, "fDenyTSConnections")
	if err != nil {
		return s, err
	}
	locDeny, err := readRegDWORD(rdpLocalPath, "fDenyTSConnections")
	if err != nil {
		return s, err
	}
	if deny := ResolveRDPValue(polDeny, locDeny); deny.Present {
		s.Enabled = RDPValue{Value: !deny.Value, Present: true}
		if polDeny.Present {
			s.EnabledSource = "group-policy"
		} else {
			s.EnabledSource = "local"
		}
	}
	polNLA, err := readRegDWORD(rdpPolicyPath, "UserAuthentication")
	if err != nil {
		return s, err
	}
	locNLA, err := readRegDWORD(rdpTcpPath, "UserAuthentication")
	if err != nil {
		return s, err
	}
	s.NLA = ResolveRDPValue(polNLA, locNLA)
	if s.NLA.Present {
		if polNLA.Present {
			s.NLASource = "group-policy"
		} else {
			s.NLASource = "local"
		}
	}
	return s, nil
}
