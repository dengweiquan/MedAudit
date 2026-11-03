package linux

import (
	"os"
	"path/filepath"
	"testing"
)

// Include 目标为目录（读失败）时不得忽略：整段解析必须报错，不误判全局值。
func TestParseSshdConfigIncludeDirError(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "conf.d")
	os.MkdirAll(sub, 0755)
	main := filepath.Join(dir, "sshd_config")
	os.WriteFile(main, []byte("PasswordAuthentication yes\nInclude conf.d\n"), 0644)
	if _, err := ParseSshdConfig(main); err == nil {
		t.Fatal("want error for unreadable include target, got nil")
	}
}

// Include 无匹配时不报错：主文件值照常解析。
func TestParseSshdConfigIncludeNoMatch(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sshd_config")
	os.WriteFile(main, []byte("PasswordAuthentication no\nInclude conf.d/*.conf\n"), 0644)
	vals, err := ParseSshdConfig(main)
	if err != nil {
		t.Fatalf("want no error, got %v", err)
	}
	if vals["passwordauthentication"] != "no" {
		t.Fatalf("want no, got %q", vals["passwordauthentication"])
	}
}
