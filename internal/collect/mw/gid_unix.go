//go:build !windows

package mw

import (
	"os"
	"syscall"
)

func statGID(info os.FileInfo) (int, bool) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Gid), true
	}
	return 0, false
}
