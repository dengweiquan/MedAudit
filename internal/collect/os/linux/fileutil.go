package linux

import (
	"os"
	"path/filepath"
	"syscall"
)

// ownerInfo 文件属主。
type ownerInfo struct {
	uid int
	gid int
}

// fileOwner 从 FileInfo 提取 uid/gid（Linux）。
func fileOwner(fi os.FileInfo) (ownerInfo, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ownerInfo{}, false
	}
	return ownerInfo{uid: int(st.Uid), gid: int(st.Gid)}, true
}

// dirOf 取父目录。
func dirOf(p string) string {
	return filepath.Dir(p)
}
