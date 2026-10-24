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
	"time"

	"medaudit/internal/license"
)

const version = "0.33.0-m33"

var flagServer string

type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

type cmdDef struct {
	name    string
	usage   string // 中文用法
	usageEN string // English usage
	fn      func([]string) error
}

func (d cmdDef) usageText() string { return T(d.usage, d.usageEN) }

var cmdList = []cmdDef{
	// 会话与上下文
	{"login", "ma login [user] — 登录（口令交互输入）", "ma login [user] — log in (password prompted)", cmdLogin},
	{"logout", "ma logout — 注销并清除本地会话", "ma logout — log out and clear the local session", cmdLogout},
	{"whoami", "ma whoami — 当前会话与上下文", "ma whoami — current session and context", cmdWhoami},
	{"token", "ma token — 生成/轮换超级令牌（原文只显示一次，请妥善保存；轮换即吊销 admin 全部会话）", "ma token — generate/rotate the super token (shown only once; save it; rotation revokes all admin sessions)", cmdToken},
	{"tokenoff", "ma tokenoff — 停用超级令牌（之后令牌登录被拒；admin 会话已吊销）", "ma tokenoff — disable the super token (token logins rejected afterwards; admin sessions revoked)", cmdTokenOff},
	{"use", "ma use [hospital] — 查看/设置当前医院上下文", "ma use [hospital] — show/set the current hospital context", cmdUse},
	{"site", "ma site — 本站医院信息", "ma site — this site's hospital info", cmdSite},
	// 平台账号
	{"userls", "ma userls — 用户列表", "ma userls — list users", cmdUserList},
	{"useradd", "ma useradd <name> [-e 口令环境变量] — 建号", "ma useradd <name> [-e password-env] — create a user", cmdUserAdd},
	{"useron", "ma useron <name> — 启用用户", "ma useron <name> — enable a user", func(a []string) error { return cmdUserDisabled(a, false) }},
	{"useroff", "ma useroff <name> — 禁用用户", "ma useroff <name> — disable a user", func(a []string) error { return cmdUserDisabled(a, true) }},
	{"userpw", "ma userpw <name> [-e 口令环境变量] — 重置口令", "ma userpw <name> [-e password-env] — reset a password", cmdUserPassword},
	// 医院（客户）
	{"hosls", "ma hosls [-j] — 医院（客户）列表", "ma hosls [-j] — list hospitals (customers)", cmdHospitalList},
	{"hosadd", "ma hosadd <id> [-n 名称] — 登记医院（客户）", "ma hosadd <id> [-n name] — register a hospital (customer)", cmdHospitalAdd},
	{"hosrm", "ma hosrm <id> [-y] — 删除医院（客户）及其全部数据", "ma hosrm <id> [-y] — delete a hospital (customer) and all its data", cmdHospitalDelete},
	// 审计对象
	{"assetls", "ma assetls [-k 类型] [-j] — 资产列表", "ma assetls [-k kind] [-j] — list assets", cmdAssetList},
	{"assetadd", "ma assetadd <类型> <端点> [-i id] [-n 名称] [-u 账号] [-h 医院] [-f labels文件] — 登记资产", "ma assetadd <kind> <endpoint> [-i id] [-n name] [-u account] [-h hospital] [-f labels-file] — register an asset", cmdAssetAdd},
	{"assetshow", "ma assetshow <id> — 资产详情", "ma assetshow <id> — asset details", cmdAssetShow},
	{"assetmod", "ma assetmod <id> [端点] [-n 名称] [-u 账号] [-f labels文件] — 修改资产", "ma assetmod <id> [endpoint] [-n name] [-u account] [-f labels-file] — modify an asset", cmdAssetMod},
	{"assetrm", "ma assetrm <id> — 删除资产登记（历史包保留）", "ma assetrm <id> — delete an asset registration (history bundles kept)", cmdAssetDelete},
	// 审计执行与评估
	{"audit", "ma audit <资产id> [-b 基线] [-e 口令环境变量] — 一键审计（按类型自动分发）；ma audit -f 清单.yaml 批量", "ma audit <asset-id> [-b baseline] [-e password-env] — one-click audit (dispatched by kind); ma audit -f list.yaml for batch", cmdAudit},
	{"eval", "ma eval <包id> [-b 基线] [-F] — 在线评估", "ma eval <bundle-id> [-b baseline] [-F] — evaluate online", cmdEvaluate},
	{"offeval", "ma offeval <包.zip> [-b 基线.json] [-o 报告.docx] [-j] [-F] — 离线评估（不依赖服务端）", "ma offeval <bundle.zip> [-b baseline.json] [-o report.docx] [-j] [-F] — offline evaluation (no server needed)", cmdOffEval},
	// 事实包
	{"bundlels", "ma bundlels [-a 资产] [-j] — 事实包列表", "ma bundlels [-a asset] [-j] — list fact bundles", cmdBundleList},
	{"bundlein", "ma bundlein <文件.zip> — 导入事实包", "ma bundlein <file.zip> — import a fact bundle", cmdBundleImport},
	{"bundleshow", "ma bundleshow <包id> [-j] — 包元数据/收据/事实构成", "ma bundleshow <bundle-id> [-j] — bundle metadata/receipt/fact composition", cmdBundleShow},
	{"bundledrift", "ma bundledrift <新包> <旧包> — 漂移对比", "ma bundledrift <new-bundle> <old-bundle> — drift comparison", cmdBundleDrift},
	{"bundleeff", "ma bundleeff <包id> [-j] — 有效权限", "ma bundleeff <bundle-id> [-j] — effective permissions", cmdBundleEffective},
	// 问题与报告
	{"find", "ma find <包id> [-c 结论] [-r 规则] [-j] [-o 清单.csv] — 问题清单", "ma find <bundle-id> [-c conclusion] [-r rule] [-j] [-o list.csv] — findings list", cmdFindings},
	{"report", "ma report <包id> [-o 报告.docx] — 生成报告并下载 Word", "ma report <bundle-id> [-o report.docx] — generate and download a Word report", cmdReport},
	{"reportls", "ma reportls — 报告列表", "ma reportls — list reports", cmdReportList},
	{"reportshow", "ma reportshow <报告id> [-j] — 报告摘要", "ma reportshow <report-id> [-j] — report summary", cmdReportShow},
	{"reportfix", "ma reportfix <报告id> [-r 规则] — 修复/回滚脚本", "ma reportfix <report-id> [-r rule] — remediation/rollback scripts", cmdReportScripts},
	// 基线与规则
	{"basels", "ma basels [-h 医院] [-j] — 基线列表", "ma basels [-h hospital] [-j] — list baselines", cmdBaselineList},
	{"baseshow", "ma baseshow <id> [-o 文件] — 查看/导出基线", "ma baseshow <id> [-o file] — view/export a baseline", cmdBaselineGet},
	{"baseadd", "ma baseadd -f 基线.json — 登记基线（文件）", "ma baseadd -f baseline.json — register a baseline (from file)", cmdBaselineApply},
	{"basediff", "ma basediff <基线A> <基线B> — 放行集差异（ID 或 .json 文件）", "ma basediff <baseline-A> <baseline-B> — allow-set diff (IDs or .json files)", cmdBaselineDiff},
	{"baseexempt", "ma baseexempt <finding-id> [-b 基线] [-y] [原因…] — 一键把问题加入基线", "ma baseexempt <finding-id> [-b baseline] [-y] [reason...] — add a finding to a baseline in one step", cmdBaselineExempt},
	{"rules", "ma rules [-j] — 规则与本站启停状态", "ma rules [-j] — rules and this site's enable/disable state", cmdRuleList},
	{"ruleoff", "ma ruleoff <规则id> <原因…> — 关闭检查项（本站）", "ma ruleoff <rule-id> <reason...> — disable a check (this site)", func(a []string) error { return cmdRuleSet(a, false) }},
	{"ruleon", "ma ruleon <规则id> — 恢复检查项", "ma ruleon <rule-id> — re-enable a check", func(a []string) error { return cmdRuleSet(a, true) }},
	// 关联、汇总、服务端
	{"corr", "ma corr [包id…] — 跨包提权路径（缺省取各资产最新包）", "ma corr [bundle-id...] — cross-bundle privilege paths (default: latest bundle per asset)", cmdCorrelate},
	{"sum", "ma sum — 医院风险汇总", "ma sum — hospital risk summary", cmdSummary},
	{"srv", "ma srv — 服务端状态", "ma srv — server status", cmdServerStatus},
	{"srvbak", "ma srvbak <备份文件> — 平台库在线备份", "ma srvbak <backup-file> — online backup of the platform database", cmdServerBackup},
	{"srvreset", "ma srvreset [-o 备份文件] [-y] — 一键清场（新客户现场：先备份，清全部数据，用户恢复默认 admin）", "ma srvreset [-o backup-file] [-y] — one-step reset for a new customer site (backs up first, wipes all data, restores default admin)", cmdServerReset},
}

var commands = func() map[string]func([]string) error {
	m := map[string]func([]string) error{}
	for _, c := range cmdList {
		m[c.name] = c.fn
	}
	return m
}()

func printIndex() {
	fmt.Fprintf(os.Stderr, T("ma — MedAudit 工程师命令行 %s\n\n", "ma — MedAudit engineer CLI %s\n\n"), version)
	fmt.Fprintln(os.Stderr, T("调用：ma <功能> [短旗标] <位置参数…>；全局 -s <url> 指定服务端。", "Usage: ma <function> [short flags] <positional args...>; global -s <url> selects the server."))
	fmt.Fprintln(os.Stderr, T("上下文（服务端/用户/当前医院）存 ~/.medaudit/session.json，用 ma use 切换医院。", "Context (server/user/current hospital) is stored in ~/.medaudit/session.json; switch hospitals with ma use."))
	fmt.Fprintln(os.Stderr)
	groups := []struct {
		title, titleEN string
		from, to       int
	}{
		{"会话与上下文", "Session & context", 0, 5}, {"平台账号", "Platform users", 5, 10}, {"医院（客户）", "Hospitals (customers)", 10, 13},
		{"审计对象", "Assets", 13, 18}, {"审计执行与评估", "Audit & evaluation", 18, 21}, {"事实包", "Fact bundles", 21, 26},
		{"问题与报告", "Findings & reports", 26, 31}, {"基线与规则", "Baselines & rules", 31, 39}, {"关联、汇总、服务端", "Correlation, summary, server", 39, len(cmdList)},
	}
	for _, g := range groups {
		fmt.Fprintf(os.Stderr, "%s%s\n", T(g.title, g.titleEN), T("：", ":"))
		for _, c := range cmdList[g.from:g.to] {
			fmt.Fprintf(os.Stderr, "  %s\n", c.usageText())
		}
		fmt.Fprintln(os.Stderr)
	}
	fmt.Fprintln(os.Stderr, T("退出码：0 正常；1 执行错误；2 业务 FAIL（-F 时）。口令永不落盘：交互输入或 -e 环境变量。", "Exit codes: 0 ok; 1 execution error; 2 business FAIL (with -F). Passwords are never stored on disk: interactive prompt or -e environment variable."))
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
			fmt.Fprintf(os.Stderr, T("旧命令名 %s 已取消，请用 ma %s …\n", "Legacy command name %s was removed; use ma %s ...\n"), invoked, fn)
			os.Exit(1)
		}
	}
	if len(args) == 0 {
		printIndex()
		return
	}
	name := args[0]
	if name == "version" || name == "-V" {
		fmt.Print(license.VersionBlock("ma", version, time.Now()))
		return
	}
	fn, ok := commands[name]
	if !ok {
		if hint, isLegacy := legacyHint(name); isLegacy {
			fmt.Fprintf(os.Stderr, T("旧形式 ma %s 已取消，请用 ma %s …\n", "Legacy form ma %s was removed; use ma %s ...\n"), name, hint)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, T("未知功能 %q\n\n", "Unknown function %q\n\n"), name)
		printIndex()
		os.Exit(1)
	}
	args = args[1:]
	if err := fn(args); err != nil {
		if ee, ok := err.(*exitError); ok {
			fmt.Fprintln(os.Stderr, T("错误：", "Error:"), ee.msg)
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, T("错误：", "Error:"), err)
		os.Exit(1)
	}
}
