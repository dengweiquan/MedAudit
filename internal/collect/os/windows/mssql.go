//go:build windows

package windows

import (
	"errors"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const mssqlInstanceNamesPath = `SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL`

// enumMSSQLInstances 枚举实例名 → 实例 ID（Instance Names\SQL 的值名 → 值）。
// 实例名键不存在 = 宿主无实例，返回空切片（不报错）；单个值读失败则跳过该实例。
func enumMSSQLInstances() ([]MSSQLInstance, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, mssqlInstanceNamesPath, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer k.Close()
	names, err := k.ReadValueNames(0)
	if err != nil {
		return nil, err
	}
	var out []MSSQLInstance
	for _, name := range names {
		id, _, err := k.GetStringValue(name)
		if err != nil {
			continue
		}
		out = append(out, MSSQLInstance{Name: name, ID: id})
	}
	return out, nil
}

// readForceEncryption 读某实例的 ForceEncryption：
// 返回 (present, value, err)：值不存在 → present=false（缺省 0）；其他错误 → err。
// 注意：本函数不读会话 encrypt_option——会话值不替代服务器策略。
func readForceEncryption(instanceID string) (bool, bool, error) {
	v, err := readRegDWORD(MSSQLSuperSocketPath(instanceID), "ForceEncryption")
	if err != nil {
		return false, false, err
	}
	if !v.Present {
		return false, false, nil
	}
	return true, v.Value, nil
}

// isRegistryDenied 判断注册表错误是否为拒绝访问（用于事实状态标注，不把所有失败都说成权限不足）。
func isRegistryDenied(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
