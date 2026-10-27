package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"medaudit/internal/facts"
)

// collectPasswdGroups 采集本地账号与组（/etc/passwd、/etc/group）。
// M8-1 关联分析需要主体清单与组成员关系（此前 OS 包只有 sudo 与进程视角）。
// rootDir 与 sudoers 根目录口径一致（默认 /etc，离线分析可指向挂载根）。
func collectPasswdGroups(b *facts.FactBundle, rootDir string, addReceipt func(facts.Receipt), execStatus *facts.ExecutionStatus) {
	if rootDir == "" {
		rootDir = "/etc"
	}
	rStart := time.Now()
	receipt := facts.Receipt{
		TemplateID: "linux.passwd_groups", TemplateVersion: "1",
		Started: rStart.UTC().Truncate(time.Second),
		Status:  "ok", Visibility: "full",
	}
	finish := func() {
		receipt.Finished = time.Now().UTC().Truncate(time.Second)
		receipt.DurationMs = receipt.Finished.Sub(receipt.Started).Milliseconds()
		addReceipt(receipt)
	}

	passwdRaw, err := os.ReadFile(filepath.Join(rootDir, "passwd"))
	if err != nil {
		receipt.Status = "partial"
		receipt.ErrorStage = "read_passwd"
		*execStatus = facts.ExecutionPartial
		finish()
		return
	}
	type passwdEnt struct {
		name, home, shell string
		uid, gid          int
	}
	var users []passwdEnt
	gidPrimary := map[int][]string{} // gid -> users（主组）
	for _, line := range strings.Split(string(passwdRaw), "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) < 7 || f[0] == "" {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		gid, _ := strconv.Atoi(f[3])
		users = append(users, passwdEnt{f[0], f[5], f[6], uid, gid})
		gidPrimary[gid] = append(gidPrimary[gid], f[0])
	}
	rows := 0
	for i, u := range users {
		system := "false"
		if u.uid < 1000 {
			system = "true"
		}
		b.Facts = append(b.Facts, facts.Fact{
			FactID: fmt.Sprintf("fact-passwd-%d", i),
			Kind:   facts.FactIdentity, Subject: u.name,
			Status: facts.StatusObserved, Source: "linux.passwd",
			Attributes: map[string]string{
				"uid": strconv.Itoa(u.uid), "gid": strconv.Itoa(u.gid),
				"home": u.home, "shell": u.shell, "system": system,
			},
		})
		rows++
	}

	groupRaw, err := os.ReadFile(filepath.Join(rootDir, "group"))
	if err != nil {
		receipt.Status = "partial"
		receipt.ErrorStage = "read_group"
		*execStatus = facts.ExecutionPartial
		receipt.RowCount = rows
		finish()
		return
	}
	edgeSeq := 0
	addEdge := func(user, group string, gid int) {
		b.Facts = append(b.Facts, facts.Fact{
			FactID: fmt.Sprintf("fact-member-%d", edgeSeq),
			Kind:   facts.FactRoleEdge, Subject: user,
			Status: facts.StatusObserved, Source: "linux.groups",
			PermissionPath: []string{group, user},
			Attributes:     map[string]string{"gid": strconv.Itoa(gid)},
		})
		edgeSeq++
		rows++
	}
	for i, line := range strings.Split(string(groupRaw), "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) < 4 || f[0] == "" {
			continue
		}
		gid, _ := strconv.Atoi(f[2])
		b.Facts = append(b.Facts, facts.Fact{
			FactID: fmt.Sprintf("fact-group-%d", i),
			Kind:   facts.FactIdentity, Subject: f[0],
			Status: facts.StatusObserved, Source: "linux.groups",
			Attributes: map[string]string{
				"entity": "group", "gid": strconv.Itoa(gid), "members": f[3],
			},
		})
		rows++
		memberSet := map[string]bool{}
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				memberSet[m] = true
			}
		}
		for _, m := range gidPrimary[gid] {
			memberSet[m] = true
		}
		for m := range memberSet {
			addEdge(m, f[0], gid)
		}
	}
	receipt.RowCount = rows
	finish()
}
