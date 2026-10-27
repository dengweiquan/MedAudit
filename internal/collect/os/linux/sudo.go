package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"medaudit/internal/facts"
)

// SudoSpec 一条 sudoers 用户授权规格（解析结果，保留原文）。
type SudoSpec struct {
	Who      string // 用户或 %组（原文第一字段，可为 #uid 形式）
	Hosts    string
	RunAs    string // 空 = 默认 (root)
	NoPasswd bool
	Commands string // 去标签后的命令规格原文
	HasAll   bool   // 命令列表含独立的 ALL
	File     string
	Raw      string
}

var sudoTags = []string{
	"NOPASSWD", "PASSWD", "NOEXEC", "EXEC", "SETENV", "NOSETENV",
	"MAIL", "NOMAIL", "FOLLOW", "NOFOLLOW", "LOG_INPUT", "NOLOG_INPUT",
	"LOG_OUTPUT", "NOLOG_OUTPUT", "INTERCEPT", "NOINTERCEPT",
}

// ParseSudoers 解析单个 sudoers 文件内容。只做审计所需的结构化提取，
// 不求完整语法覆盖：别名定义/Defaults/include 行跳过（sudoers.d 由调用方逐个文件解析）。
func ParseSudoers(content, file string) []SudoSpec {
	// 续行合并
	content = strings.ReplaceAll(content, "\\\n", " ")
	var out []SudoSpec
	for _, line := range strings.Split(content, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.HasPrefix(trim, "Defaults") || strings.HasPrefix(trim, "@include") ||
			strings.HasPrefix(trim, "#include") {
			continue
		}
		for _, alias := range []string{"User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias"} {
			if strings.HasPrefix(trim, alias) {
				trim = "" // 标记跳过
				break
			}
		}
		if trim == "" {
			continue
		}
		eq := strings.Index(trim, "=")
		if eq < 0 {
			continue // 非用户规格行
		}
		left := strings.Fields(strings.TrimSpace(trim[:eq]))
		if len(left) == 0 {
			continue
		}
		spec := SudoSpec{Who: left[0], File: file, Raw: trim}
		if len(left) > 1 {
			spec.Hosts = strings.Join(left[1:], " ")
		}
		right := strings.TrimSpace(trim[eq+1:])
		if strings.HasPrefix(right, "(") {
			if close := strings.Index(right, ")"); close >= 0 {
				spec.RunAs = right[1:close]
				right = strings.TrimSpace(right[close+1:])
			}
		}
		// 判定 NOPASSWD 并剥离已知标签
		upper := strings.ToUpper(right)
		spec.NoPasswd = strings.Contains(upper, "NOPASSWD:")
		cmds := right
		for _, tag := range sudoTags {
			re := regexp.MustCompile(`(?i)\b` + tag + `\s*:\s*`)
			cmds = re.ReplaceAllString(cmds, "")
		}
		spec.Commands = strings.TrimSpace(cmds)
		for _, tok := range strings.Split(spec.Commands, ",") {
			if strings.TrimSpace(tok) == "ALL" {
				spec.HasAll = true
			}
		}
		out = append(out, spec)
	}
	return out
}

// collectSudo 采集 /etc/sudoers 与 sudoers.d（M4-4b）。无 sudo 环境（文件缺失）
// 产出 unsupported 事实而非静默缺席：核查结论需要知道“查过、没有”。
func collectSudo(b *facts.FactBundle, dir string, addReceipt func(facts.Receipt), execStatus *facts.ExecutionStatus) {
	if dir == "" {
		dir = "/etc"
	}
	rStart := time.Now()
	receipt := facts.Receipt{
		TemplateID: "linux.sudo", TemplateVersion: "1",
		Started: rStart.UTC().Truncate(time.Second),
		Status:  "ok", Visibility: "full",
	}
	finish := func() {
		receipt.Finished = time.Now().UTC().Truncate(time.Second)
		receipt.DurationMs = receipt.Finished.Sub(receipt.Started).Milliseconds()
		addReceipt(receipt)
	}

	mainPath := filepath.Join(dir, "sudoers")
	raw, err := os.ReadFile(mainPath)
	if err != nil {
		if os.IsNotExist(err) {
			b.Facts = append(b.Facts, facts.Fact{
				FactID: "fact-sudo-absent", Kind: facts.FactAccountConfig,
				Subject: "sudoers", Status: facts.StatusUnsupported, Source: "linux.sudo",
				Attributes: map[string]string{"present": "false", "dir": dir},
			})
			receipt.RowCount = 0
			finish()
			return
		}
		receipt.Status = "denied"
		receipt.ErrorStage = "read"
		b.Facts = append(b.Facts, facts.Fact{
			FactID: "fact-sudo-denied", Kind: facts.FactAccountConfig,
			Subject: "sudoers", Status: facts.StatusPermissionDenied, Source: "linux.sudo",
			Attributes: map[string]string{"error": err.Error(), "dir": dir},
		})
		*execStatus = facts.ExecutionPartial
		finish()
		return
	}

	specs := ParseSudoers(string(raw), mainPath)
	dDir := filepath.Join(dir, "sudoers.d")
	if entries, derr := os.ReadDir(dDir); derr == nil {
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || strings.Contains(name, ".") || strings.HasSuffix(name, "~") {
				continue // sudo 本身会忽略含 . 或以 ~ 结尾的文件
			}
			data, rerr := os.ReadFile(filepath.Join(dDir, name))
			if rerr != nil {
				continue
			}
			specs = append(specs, ParseSudoers(string(data), filepath.Join(dDir, name))...)
		}
	}
	for i, sp := range specs {
		nopw := "false"
		if sp.NoPasswd {
			nopw = "true"
		}
		hasAll := "false"
		if sp.HasAll {
			hasAll = "true"
		}
		runas := sp.RunAs
		if runas == "" {
			runas = "(root)"
		}
		b.Facts = append(b.Facts, facts.Fact{
			FactID:  fmt.Sprintf("fact-sudo-%d", i),
			Kind:    facts.FactAccountConfig,
			Subject: sp.Who,
			Status:  facts.StatusObserved,
			Source:  "linux.sudo",
			Attributes: map[string]string{
				"hosts": sp.Hosts, "runas": runas, "nopasswd": nopw,
				"commands": sp.Commands, "commands_all": hasAll,
				"file": sp.File, "raw": sp.Raw,
			},
		})
	}
	receipt.RowCount = len(specs)
	finish()
}
