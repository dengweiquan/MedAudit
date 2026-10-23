package main

import (
	"os"
	"strings"
)

// 界面语言（M28）：中文环境用中文，其他环境用英文。
// 判定顺序与 locale 惯例一致：LC_ALL > LC_MESSAGES > LANG；
// 取值以 zh 开头（zh_CN、zh_TW、zh-Hans…）即中文环境，其余
// （en、fr、C、POSIX、未设置）一律英文。
var uiEnglish = detectUIEnglish()

func detectUIEnglish() bool {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		v := strings.TrimSpace(os.Getenv(k))
		if v == "" {
			continue
		}
		return !strings.HasPrefix(strings.ToLower(v), "zh")
	}
	return true
}

// T 按界面语言取文案（服务端返回的文案不经此函数、原样透传）。
func T(zh, en string) string {
	if uiEnglish {
		return en
	}
	return zh
}
