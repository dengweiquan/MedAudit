//go:build !windows

package mw

import (
	"os"
	"syscall"
)

func statUID(info os.FileInfo) (int, bool) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), true
	}
	return 0, false
}
