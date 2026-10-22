//go:build windows

// Package windows 实现 Windows Server 目标的只读元数据采集：
// 服务配置（SCM）、实际进程令牌、本地组与文件 ACL。全部只读，不修改目标。
package windows

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ServiceInfo 单个 Windows 服务的采集信息。
type ServiceInfo struct {
	Name           string
	DisplayName    string
	StartType      uint32
	BinaryPath     string
	ServiceAccount string // 服务配置的运行身份（lpServiceStartName）
	PID            uint32 // 运行中服务的进程 ID，0 表示未运行
	State          uint32
	ConfigErr      error // 配置查询失败时记录，不中断整体采集
}

// enumServices 枚举全部 Win32 服务并查询各自配置。
func enumServices() ([]ServiceInfo, error) {
	mgr, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE|windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, fmt.Errorf("OpenSCManager: %w", err)
	}
	defer windows.CloseServiceHandle(mgr)

	var bytesNeeded, servicesReturned, resumeHandle uint32
	err = windows.EnumServicesStatusEx(mgr, windows.SC_ENUM_PROCESS_INFO,
		windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL,
		nil, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nil)
	if err != windows.ERROR_MORE_DATA {
		return nil, fmt.Errorf("EnumServicesStatusEx(探测): %w", err)
	}
	buf := make([]byte, bytesNeeded)
	err = windows.EnumServicesStatusEx(mgr, windows.SC_ENUM_PROCESS_INFO,
		windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL,
		&buf[0], uint32(len(buf)), &bytesNeeded, &servicesReturned, &resumeHandle, nil)
	if err != nil {
		return nil, fmt.Errorf("EnumServicesStatusEx: %w", err)
	}
	raw := (*[1 << 20]windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0]))[:servicesReturned:servicesReturned]

	out := make([]ServiceInfo, 0, servicesReturned)
	for _, es := range raw {
		si := ServiceInfo{
			Name:        windows.UTF16PtrToString(es.ServiceName),
			DisplayName: windows.UTF16PtrToString(es.DisplayName),
			PID:         es.ServiceStatusProcess.ProcessId,
			State:       es.ServiceStatusProcess.CurrentState,
		}
		bin, account, startType, qerr := queryServiceConfig(mgr, si.Name)
		if qerr != nil {
			si.ConfigErr = qerr
		} else {
			si.BinaryPath, si.ServiceAccount, si.StartType = bin, account, startType
		}
		out = append(out, si)
	}
	return out, nil
}

// queryServiceConfig 查询单个服务的二进制路径、运行身份与启动类型。
func queryServiceConfig(mgr windows.Handle, name string) (binPath, account string, startType uint32, err error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", "", 0, err
	}
	h, err := windows.OpenService(mgr, namePtr, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return "", "", 0, fmt.Errorf("OpenService: %w", err)
	}
	defer windows.CloseServiceHandle(h)

	var bytesNeeded uint32
	_ = windows.QueryServiceConfig(h, nil, 0, &bytesNeeded)
	buf := make([]byte, bytesNeeded)
	qc := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
	if err := windows.QueryServiceConfig(h, qc, uint32(len(buf)), &bytesNeeded); err != nil {
		return "", "", 0, fmt.Errorf("QueryServiceConfig: %w", err)
	}
	return windows.UTF16PtrToString(qc.BinaryPathName),
		windows.UTF16PtrToString(qc.ServiceStartName),
		qc.StartType, nil
}

// startTypeName 启动类型可读名。
func startTypeName(t uint32) string {
	switch t {
	case windows.SERVICE_AUTO_START:
		return "auto"
	case windows.SERVICE_BOOT_START:
		return "boot"
	case windows.SERVICE_DEMAND_START:
		return "demand"
	case windows.SERVICE_DISABLED:
		return "disabled"
	case windows.SERVICE_SYSTEM_START:
		return "system"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// serviceStateName 服务状态可读名。
func serviceStateName(s uint32) string {
	switch s {
	case windows.SERVICE_CONTINUE_PENDING:
		return "continue_pending"
	case windows.SERVICE_PAUSE_PENDING:
		return "pause_pending"
	case windows.SERVICE_PAUSED:
		return "paused"
	case windows.SERVICE_RUNNING:
		return "running"
	case windows.SERVICE_START_PENDING:
		return "start_pending"
	case windows.SERVICE_STOP_PENDING:
		return "stop_pending"
	case windows.SERVICE_STOPPED:
		return "stopped"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}
