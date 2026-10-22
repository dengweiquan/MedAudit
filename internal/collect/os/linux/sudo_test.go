package linux

import "testing"

func TestParseSudoersBasic(t *testing.T) {
	content := `
# 注释行
Defaults env_reset
root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL
deploy ALL=(ALL) NOPASSWD: ALL
ops ALL=(root) /usr/bin/systemctl restart app, /usr/bin/journalctl
User_Alias ADMINS = alice, bob
`
	specs := ParseSudoers(content, "test")
	if len(specs) != 4 {
		t.Fatalf("期望 4 条规格，got %d: %+v", len(specs), specs)
	}
	byWho := map[string]SudoSpec{}
	for _, s := range specs {
		byWho[s.Who] = s
	}
	if !byWho["deploy"].NoPasswd || !byWho["deploy"].HasAll {
		t.Fatalf("deploy 应为 NOPASSWD+ALL: %+v", byWho["deploy"])
	}
	if byWho["%sudo"].NoPasswd || !byWho["%sudo"].HasAll {
		t.Fatalf("%%sudo 应为需口令 ALL: %+v", byWho["%sudo"])
	}
	if byWho["ops"].HasAll {
		t.Fatalf("ops 命令已收窄，不应判 ALL: %+v", byWho["ops"])
	}
	if byWho["root"].RunAs != "ALL:ALL" {
		t.Fatalf("root runas 解析错误: %+v", byWho["root"])
	}
}

func TestParseSudoersTagsAndMultipleSpecs(t *testing.T) {
	content := "backup ALL=(ALL) NOPASSWD: /usr/bin/rsync, PASSWD: /usr/bin/tar\n"
	specs := ParseSudoers(content, "test")
	if len(specs) != 1 {
		t.Fatalf("期望 1 条，got %d", len(specs))
	}
	if !specs[0].NoPasswd || specs[0].HasAll {
		t.Fatalf("解析错误: %+v", specs[0])
	}
	if specs[0].Commands != "/usr/bin/rsync, /usr/bin/tar" {
		t.Fatalf("标签剥离错误: %q", specs[0].Commands)
	}
}
