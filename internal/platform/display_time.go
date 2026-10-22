package platform

import (
	"os"
	"strings"
	"time"
	_ "time/tzdata" // 保证最小环境下 LoadLocation 可用
)

// 报告显示时区：平台存储统一 UTC，仅在渲染（Word 等）时转换。
// 默认 Asia/Shanghai（与产品既有 fmtTimeCN 口径一致），可经环境
// 变量 MEDAUDIT_DISPLAY_TZ 覆盖（IANA 时区名）。
var displayZone = loadDisplayZone()

func loadDisplayZone() *time.Location {
	if name := os.Getenv("MEDAUDIT_DISPLAY_TZ"); name != "" {
		if loc, err := time.LoadLocation(name); err == nil {
			return loc
		}
	}
	if loc, err := time.LoadLocation("Asia/Shanghai"); err == nil {
		return loc
	}
	return time.FixedZone("CST", 8*3600)
}

// parseStoredTime 解析平台存储的时间字符串（均为 UTC）：RFC3339
// 或 "2006-01-02 15:04:05"（可带小数秒/缺秒）。
func parseStoredTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	for _, layout := range []string{"2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05", "2006-01-02 15:04"} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// DisplayTime 把存储的 UTC 时间渲染为显示时区的同形字符串；
// 无法解析时原样返回（不吞数据）。
func DisplayTime(s string) string {
	if t, ok := parseStoredTime(s); ok {
		return t.In(displayZone).Format("2006-01-02 15:04:05")
	}
	return s
}
