//go:build windows

package windows

import (
	"errors"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const mssqlInstanceNamesPath = `SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL`

// enumMSSQLInstances 枚举实例名 → 实例 ID（Instance Names\SQL 的值名 → 值）。
// 返回（实例，跳过数，错误）：实例名键不存在 = 宿主无实例，返回空切片（不报错）；
// 单个值读失败不再静默跳过——跳过数由调用方汇总为 partial 收据，否则一次
// 枚举失败会被读成“无实例”（不适用）或漏掉违规实例而误判 PASS。
func enumMSSQLInstances() ([]MSSQLInstance, int, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, mssqlInstanceNamesPath, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	defer k.Close()
	names, err := k.ReadValueNames(0)
	if err != nil {
		return nil, 0, err
	}
	var out []MSSQLInstance
	skipped := 0
	for _, name := range names {
		id, _, err := k.GetStringValue(name)
		if err != nil {
			skipped++
			continue
		}
		out = append(out, MSSQLInstance{Name: name, ID: id})
	}
	return out, skipped, nil
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
