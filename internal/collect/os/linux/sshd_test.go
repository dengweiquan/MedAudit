package linux

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParseSshdIncludeFirstWinsAndMatchCutoff(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "ssh", "conf.d", "00.conf"), "PermitRootLogin yes\n")
	writeFile(t, filepath.Join(root, "ssh", "sshd_config"),
		"Include conf.d/*.conf\n"+
			"PasswordAuthentication yes\n"+
			"PasswordAuthentication no\n"+
			"Match User bob\n"+
			"  PermitRootLogin no\n"+
			"  PasswordAuthentication no\n")
	vals, err := ParseSshdConfig(filepath.Join(root, "ssh", "sshd_config"))
	if err != nil {
		t.Fatal(err)
	}
	// Include 先展开：conf.d 的 PermitRootLogin=yes 胜出，Match 块的 no 被忽略
	if vals["permitrootlogin"] != "yes" {
		t.Fatalf("permitrootlogin = %q, want yes", vals["permitrootlogin"])
	}
	// 同文件内首个生效值胜出
	if vals["passwordauthentication"] != "yes" {
		t.Fatalf("passwordauthentication = %q, want yes", vals["passwordauthentication"])
	}
}

func TestParseSshdMatchOnlyDirectivesIgnored(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "ssh", "sshd_config"),
		"Match User bob\n  PasswordAuthentication no\n")
	vals, err := ParseSshdConfig(filepath.Join(root, "ssh", "sshd_config"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := vals["passwordauthentication"]; ok {
		t.Fatalf("Match 块内指令不应计入全局值，got %+v", vals)
	}
}

func TestParseSshdIncludeCycleTerminates(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "ssh", "a.conf"),
		"Include b.conf\nPasswordAuthentication no\n")
	writeFile(t, filepath.Join(root, "ssh", "b.conf"),
		"Include a.conf\nPermitRootLogin yes\n")
	writeFile(t, filepath.Join(root, "ssh", "sshd_config"), "Include a.conf\n")
	vals, err := ParseSshdConfig(filepath.Join(root, "ssh", "sshd_config"))
	if err != nil {
		t.Fatal(err)
	}
	if vals["passwordauthentication"] != "no" || vals["permitrootlogin"] != "yes" {
		t.Fatalf("循环 Include 解析错误，got %+v", vals)
	}
}
