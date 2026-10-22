//go:build windows

package mw

import "os"

func statGID(info os.FileInfo) (int, bool) {
	return 0, false
}
