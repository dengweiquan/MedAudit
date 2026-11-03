package windows

import "strconv"

// PasswordPolicy NetUserModalsGet 结果（秒为单位的原始值 + 覆盖范围）。
// TIMEQ_FOREVER（0xFFFFFFFF）表示永不过期，调用方不得把它换算成天数。
type PasswordPolicy struct {
	MinLength          uint32
	MaxAgeSec          uint32
	MinAgeSec          uint32
	HistLen            uint32
	ForceLogoffSec     uint32
	LockoutDurationSec uint32
	LockoutWindowSec   uint32
	LockoutThreshold   uint32
	Scope              string // "local-sam" | "domain-default" | "unknown"
	Role               string // "workgroup" | "domain-member" | "domain-controller" | "unknown"
}

// passwordScopeForRole 由机器角色定覆盖范围（纯函数，可单测）：
// 域控返回域默认策略；工作组与域成员均返回本地 SAM 策略——域成员本机的查询不等于域账号默认策略，
// 域账号的默认策略不在本 API 覆盖内；角色未知时不猜测，返回 unknown。
func passwordScopeForRole(role string) string {
	switch role {
	case "domain-controller":
		return "domain-default"
	case "workgroup", "domain-member":
		return "local-sam"
	default:
		return "unknown"
	}
}

// TimeqForever NetUserModalsGet 的永不过期特殊值（DWORD 全 1）。
const TimeqForever = 0xFFFFFFFF

// PasswordPolicyAttributes 把策略映射为事实属性（全部为原始数值字符串，不做单位换算）。
func PasswordPolicyAttributes(p PasswordPolicy) map[string]string {
	return map[string]string{
		"scope":                p.Scope,
		"machine_role":         p.Role,
		"min_password_length":  strconv.FormatUint(uint64(p.MinLength), 10),
		"max_password_age_sec": strconv.FormatUint(uint64(p.MaxAgeSec), 10),
		"min_password_age_sec": strconv.FormatUint(uint64(p.MinAgeSec), 10),
		"password_hist_len":    strconv.FormatUint(uint64(p.HistLen), 10),
		"force_logoff_sec":     strconv.FormatUint(uint64(p.ForceLogoffSec), 10),
		"lockout_duration_sec": strconv.FormatUint(uint64(p.LockoutDurationSec), 10),
		"lockout_window_sec":   strconv.FormatUint(uint64(p.LockoutWindowSec), 10),
		"lockout_threshold":    strconv.FormatUint(uint64(p.LockoutThreshold), 10),
	}
}
