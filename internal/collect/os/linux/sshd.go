package linux

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"medaudit/internal/facts"
)

// sshdWatched 远程管理加固关注的 sshd 指令（与 sshd 语义一致：首个生效值胜出）。
var sshdWatched = map[string]bool{
	"passwordauthentication": true,
	"permitrootlogin":        true,
}

// ParseSshdConfig 解析主配置文件及其 Include 文件，返回首个生效值。
// Match 块之后的条件指令不计入全局值；Include 循环由 visited 阻断。
func ParseSshdConfig(mainPath string) (map[string]string, error) {
	out := map[string]string{}
	visited := map[string]bool{}
	if err := parseSshdFile(mainPath, visited, out); err != nil {
		return nil, err
	}
	return out, nil
}

func parseSshdFile(path string, visited map[string]bool, out map[string]string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	if visited[abs] {
		return nil
	}
	visited[abs] = true
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		kw := strings.ToLower(fields[0])
		if kw == "match" {
			return nil // Match 块之后均为条件指令，不计入全局值
		}
		if kw == "include" {
			for _, pat := range fields[1:] {
				if !filepath.IsAbs(pat) {
					pat = filepath.Join(dir, pat)
				}
				matches, _ := filepath.Glob(pat)
				for _, m := range matches {
					_ = parseSshdFile(m, visited, out)
				}
			}
			continue
		}
		if !sshdWatched[kw] || len(fields) < 2 {
			continue
		}
		if _, ok := out[kw]; !ok {
			out[kw] = strings.ToLower(fields[1])
		}
	}
	return nil
}

// collectSshd 采集 sshd 全局鉴别配置（linux.sshd v1）。
// dir 为 etc 根目录（与 sudoers 共用缺省 /etc），主文件为 <dir>/ssh/sshd_config。
func collectSshd(b *facts.FactBundle, dir string, addReceipt func(facts.Receipt), execStatus *facts.ExecutionStatus) {
	rStart := time.Now()
	receipt := facts.Receipt{
		TemplateID: "linux.sshd", TemplateVersion: "1",
		Started: rStart.UTC().Truncate(time.Second),
		Status:  "ok", Visibility: "full",
	}
	finish := func() {
		receipt.Finished = time.Now().UTC().Truncate(time.Second)
		receipt.DurationMs = receipt.Finished.Sub(receipt.Started).Milliseconds()
		addReceipt(receipt)
	}
	if dir == "" {
		dir = "/etc"
	}
	mainPath := filepath.Join(dir, "ssh", "sshd_config")
	vals, err := ParseSshdConfig(mainPath)
	if err != nil {
		if os.IsNotExist(err) {
			b.Facts = append(b.Facts, facts.Fact{
				FactID: "fact-sshd-absent", Kind: facts.FactAccountConfig,
				Subject: "sshd_config", Status: facts.StatusUnsupported, Source: "linux.sshd",
				Attributes: map[string]string{"present": "false", "file": mainPath},
			})
			receipt.RowCount = 0
			finish()
			return
		}
		b.Facts = append(b.Facts, facts.Fact{
			FactID: "fact-sshd-denied", Kind: facts.FactAccountConfig,
			Subject: "sshd_config", Status: facts.StatusPermissionDenied, Source: "linux.sshd",
			Attributes: map[string]string{"error": err.Error(), "file": mainPath},
		})
		receipt.Status = "failed"
		receipt.ErrorStage = "read"
		receipt.Error = err.Error()
		finish()
		return
	}
	b.Facts = append(b.Facts, facts.Fact{
		FactID: "fact-sshd-1", Kind: facts.FactAccountConfig,
		Subject: "sshd_config", Status: facts.StatusObserved, Source: "linux.sshd",
		Attributes: map[string]string{
			"present": "true", "file": mainPath,
			"password_authentication": vals["passwordauthentication"],
			"permit_root_login":       vals["permitrootlogin"],
		},
	})
	receipt.RowCount = 1
	finish()
}
