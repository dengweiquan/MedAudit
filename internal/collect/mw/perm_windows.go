//go:build windows

package mw

import "os"

// Windows 上不取 POSIX uid（M7-1 的 Tomcat/Nginx 采集面向 Linux 主机）。
func statUID(info os.FileInfo) (int, bool) {
	return 0, false
}
