package linux

import (
	"strings"
	"testing"
)

// M19：缺省服务枚举的输出解析。
func TestParseRunningUnits(t *testing.T) {
	out := "ssh.service loaded active running OpenBSD Secure Shell server\n" +
		"docker.service loaded active running Docker Application Container Engine\n" +
		"cron.service loaded active running Regular background program processing daemon\n" +
		"dbus.service loaded active running D-Bus System Message Bus\n"
	got := parseRunningUnits(out)
	if len(got) != 4 || got[0] != "ssh.service" || got[3] != "dbus.service" {
		t.Fatalf("解析不符: %v", got)
	}
	// 非 service 行与空行跳过；注入字符行跳过
	out2 := "\nfoo.timer loaded active waiting x\nbad;rm.service loaded active running x\nok.service loaded active running x\n"
	got2 := parseRunningUnits(out2)
	if len(got2) != 1 || got2[0] != "ok.service" {
		t.Fatalf("过滤不符: %v", got2)
	}
	// 上限 50
	var sb strings.Builder
	for i := 0; i < 60; i++ {
		sb.WriteString("s.service loaded active running x\n")
	}
	if n := len(parseRunningUnits(sb.String())); n != 50 {
		t.Fatalf("上限不符: %d", n)
	}
	if n := len(parseRunningUnits("")); n != 0 {
		t.Fatalf("空输出应为空: %d", n)
	}
}
