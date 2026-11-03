package windows

// MSSQLInstance SQL Server 实例（名 → 注册表实例 ID）。
type MSSQLInstance struct {
	Name string
	ID   string
}

// MSSQLSuperSocketPath 某实例的 SuperSocketNetLib 注册表路径。
func MSSQLSuperSocketPath(instanceID string) string {
	return `SOFTWARE\Microsoft\Microsoft SQL Server\` + instanceID + `\MSSQLServer\SuperSocketNetLib`
}

// MSSQLForceEncryptionAttrs 返回单实例 ForceEncryption 的 Observed 事实属性。
// present=false 表示值缺失，取缺省 0（未强制）并标注 value_missing；
// effective 恒为 unknown：注册表值只证明“已配置”，重启后生效状态未验证。
func MSSQLForceEncryptionAttrs(inst MSSQLInstance, regPath string, present, value bool) map[string]string {
	attrs := map[string]string{
		"instance_id":   inst.ID,
		"registry_path": regPath,
		"effective":     "unknown",
	}
	if !present {
		attrs["force_encryption"] = "0"
		attrs["value_missing"] = "true"
	} else if value {
		attrs["force_encryption"] = "1"
	} else {
		attrs["force_encryption"] = "0"
	}
	return attrs
}
