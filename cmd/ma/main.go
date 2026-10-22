// ma — MedAudit 工程师命令行。
//
// 只有一个命令 ma，第二个词是功能（ma login、ma assetls、ma audit、
// ma find、ma report、ma rules、ma srv…）：一功能一事；目标（ID/端点）
// 一律位置参数；选项只用单字母短旗标（-u 用户、-n 名称、-b 基线、
// -o 输出、-f 文件、-j JSON、-e 口令环境变量、-h 医院覆盖、-s 服务端
// 地址）。当前医院/服务端/登录用户存会话上下文
// （~/.medaudit/session.json），不逐条命令重复声明。
//
// 旧的 ma* 多调用符号链接形式（maaudit、mafind…）已取消，只保留
// ma <功能> 一种形式。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const version = "0.25.0-m23"

var flagServer string

type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

type cmdDef struct {
	name  string
	usage string
	fn    func([]string) error
}

var cmdList = []cmdDef{
	// 会话与上下文
	{"login", "ma login [user] — 登录（口令交互输入）", cmdLogin},
	{"logout", "ma logout — 注销并清除本地会话", cmdLogout},
	{"whoami", "ma whoami — 当前会话与上下文", cmdWhoami},
	{"use", "ma use [hospital] — 查看/设置当前医院上下文", cmdUse},
	{"site", "ma site — 本站医院信息", cmdSite},
	// 平台账号
	{"userls", "ma userls — 用户列表", cmdUserList},
	{"useradd", "ma useradd <name> [-e 口令环境变量] — 建号", cmdUserAdd},
	{"useron", "ma useron <name> — 启用用户", func(a []string) error { return cmdUserDisabled(a, false) }},
	{"useroff", "ma useroff <name> — 禁用用户", func(a []string) error { return cmdUserDisabled(a, true) }},
	{"userpw", "ma userpw <name> [-e 口令环境变量] — 重置口令", cmdUserPassword},
	// 审计对象
	{"assetls", "ma assetls [-k 类型] [-j] — 资产列表", cmdAssetList},
	{"assetadd", "ma assetadd <类型> <端点> [-i id] [-n 名称] [-u 账号] [-h 医院] [-f labels文件] — 登记资产", cmdAssetAdd},
	{"assetshow", "ma assetshow <id> — 资产详情", cmdAssetShow},
	{"assetmod", "ma assetmod <id> [端点] [-n 名称] [-u 账号] [-f labels文件] — 修改资产", cmdAssetMod},
	{"assetrm", "ma assetrm <id> — 删除资产登记（历史包保留）", cmdAssetDelete},
	// 审计执行与评估
	{"audit", "ma audit <资产id> [-b 基线] [-e 口令环境变量] — 一键审计（按类型自动分发）；ma audit -f 清单.yaml 批量", cmdAudit},
	{"eval", "ma eval <包id> [-b 基线] [-F] — 在线评估", cmdEvaluate},
	{"offeval", "ma offeval <包.zip> [-b 基线.json] [-o 报告.docx] [-j] [-F] — 离线评估（不依赖服务端）", cmdOffEval},
	// 事实包
	{"bundlels", "ma bundlels [-a 资产] [-j] — 事实包列表", cmdBundleList},
	{"bundlein", "ma bundlein <文件.zip> — 导入事实包", cmdBundleImport},
	{"bundleshow", "ma bundleshow <包id> [-j] — 包元数据/收据/事实构成", cmdBundleShow},
	{"bundledrift", "ma bundledrift <新包> <旧包> — 漂移对比", cmdBundleDrift},
	{"bundleeff", "ma bundleeff <包id> [-j] — 有效权限", cmdBundleEffective},
	// 问题与报告
	{"find", "ma find <包id> [-c 结论] [-r 规则] [-j] [-o 清单.csv] — 问题清单", cmdFindings},
	{"report", "ma report <包id> [-o 报告.docx] — 生成报告并下载 Word", cmdReport},
	{"reportls", "ma reportls — 报告列表", cmdReportList},
	{"reportshow", "ma reportshow <报告id> [-j] — 报告摘要", cmdReportShow},
	{"reportfix", "ma reportfix <报告id> [-r 规则] — 修复/回滚脚本", cmdReportScripts},
	// 基线与规则
	{"basels", "ma basels [-h 医院] [-j] — 基线列表", cmdBaselineList},
	{"baseshow", "ma baseshow <id> [-o 文件] — 查看/导出基线", cmdBaselineGet},
	{"baseadd", "ma baseadd -f 基线.json — 登记基线（文件）", cmdBaselineApply},
	{"basediff", "ma basediff <基线A> <基线B> — 放行集差异（ID 或 .json 文件）", cmdBaselineDiff},
	{"baseexempt", "ma baseexempt <finding-id> [-b 基线] [-y] [原因…] — 一键把问题加入基线", cmdBaselineExempt},
	{"rules", "ma rules [-j] — 规则与本站启停状态", cmdRuleList},
	{"ruleoff", "ma ruleoff <规则id> <原因…> — 关闭检查项（本站）", func(a []string) error { return cmdRuleSet(a, false) }},
	{"ruleon", "ma ruleon <规则id> — 恢复检查项", func(a []string) error { return cmdRuleSet(a, true) }},
	// 关联、汇总、服务端
	{"corr", "ma corr [包id…] — 跨包提权路径（缺省取各资产最新包）", cmdCorrelate},
	{"sum", "ma sum — 医院风险汇总", cmdSummary},
	{"srv", "ma srv — 服务端状态", cmdServerStatus},
	{"srvbak", "ma srvbak <备份文件> — 平台库在线备份", cmdServerBackup},
}

var commands = func() map[string]func([]string) error {
	m := map[string]func([]string) error{}
	for _, c := range cmdList {
		m[c.name] = c.fn
	}
	return m
}()

func printIndex() {
	fmt.Fprintf(os.Stderr, "ma — MedAudit 工程师命令行 %s\n\n", version)
	fmt.Fprintln(os.Stderr, "调用：ma <功能> [短旗标] <位置参数…>；全局 -s <url> 指定服务端。")
	fmt.Fprintf(os.Stderr, "上下文（服务端/用户/当前医院）存 ~/.medaudit/session.json，用 ma use 切换医院。\n\n")
	group := ""
	groups := []struct {
		title    string
		from, to int
	}{
		{"会话与上下文", 0, 5}, {"平台账号", 5, 10}, {"审计对象", 10, 15},
		{"审计执行与评估", 15, 18}, {"事实包", 18, 23}, {"问题与报告", 23, 28},
		{"基线与规则", 28, 36}, {"关联、汇总、服务端", 36, len(cmdList)},
	}
	_ = group
	for _, g := range groups {
		fmt.Fprintf(os.Stderr, "%s：\n", g.title)
		for _, c := range cmdList[g.from:g.to] {
			fmt.Fprintf(os.Stderr, "  %s\n", c.usage)
		}
		fmt.Fprintln(os.Stderr)
	}
	fmt.Fprintln(os.Stderr, "退出码：0 正常；1 执行错误；2 业务 FAIL（-F 时）。口令永不落盘：交互输入或 -e 环境变量。")
}

func legacyHint(name string) (string, bool) {
	// 旧形式：maaudit / marulels 等（ma + 功能词，或改名前的 marulels）
	if !strings.HasPrefix(name, "ma") || len(name) <= 2 {
		return "", false
	}
	fn := strings.TrimPrefix(name, "ma")
	if fn == "rulels" {
		fn = "rules"
	}
	if _, ok := commands[fn]; ok {
		return fn, true
	}
	return "", false
}

func main() {
	args := os.Args[1:]
	for len(args) >= 2 && args[0] == "-s" {
		flagServer = args[1]
		args = args[2:]
	}
	// 旧符号链接名（maaudit 等）直接执行时：提示新形式，不再分发。
	invoked := filepath.Base(os.Args[0])
	if invoked != "ma" && invoked != "ma.exe" {
		if fn, ok := legacyHint(invoked); ok {
			fmt.Fprintf(os.Stderr, "旧命令名 %s 已取消，请用 ma %s …\n", invoked, fn)
			os.Exit(1)
		}
	}
	if len(args) == 0 {
		printIndex()
		return
	}
	name := args[0]
	if name == "version" {
		fmt.Println("ma", version)
		return
	}
	fn, ok := commands[name]
	if !ok {
		if hint, isLegacy := legacyHint(name); isLegacy {
			fmt.Fprintf(os.Stderr, "旧形式 ma %s 已取消，请用 ma %s …\n", name, hint)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "未知功能 %q\n\n", name)
		printIndex()
		os.Exit(1)
	}
	args = args[1:]
	if err := fn(args); err != nil {
		if ee, ok := err.(*exitError); ok {
			fmt.Fprintln(os.Stderr, "错误：", ee.msg)
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "错误：", err)
		os.Exit(1)
	}
}
