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
}

// TimeqForever NetUserModalsGet 的永不过期特殊值（DWORD 全 1）。
const TimeqForever = 0xFFFFFFFF

// PasswordPolicyAttributes 把策略映射为事实属性（全部为原始数值字符串，不做单位换算）。
func PasswordPolicyAttributes(p PasswordPolicy) map[string]string {
	return map[string]string{
		"scope":                p.Scope,
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
