// ma — MedAudit 工程师命令行（M23，按 HP-UX LVM 风格重规划）。
//
// 命令族 = ma 前缀 + 对象 + 固定动作词（malogin、maassetadd、mabundleshow…），
// 一命令一件事；目标（ID/端点）一律位置参数；选项只用单字母短旗标
// （-u 用户、-n 名称、-b 基线、-o 输出、-f 文件、-j JSON、-e 口令环境变量、
// -h 医院覆盖、-s 服务端地址）。当前医院/服务端/登录用户存会话上下文
// （~/.medaudit/session.json），不逐条命令重复声明。
//
// 两种调用形式等价：符号链接名直接执行（maaudit x），或 ma 作分发器
// （ma audit x / ma maaudit x）。老 medauditctl 命令族自 0.25.0 起移除。
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
	{"malogin", "malogin [user] — 登录（口令交互输入）", cmdLogin},
	{"malogout", "malogout — 注销并清除本地会话", cmdLogout},
	{"mawhoami", "mawhoami — 当前会话与上下文", cmdWhoami},
	{"mause", "mause [hospital] — 查看/设置当前医院上下文", cmdUse},
	{"masite", "masite — 本站医院信息", cmdSite},
	// 平台账号
	{"mauserls", "mauserls — 用户列表", cmdUserList},
	{"mauseradd", "mauseradd <name> [-e 口令环境变量] — 建号", cmdUserAdd},
	{"mauseron", "mauseron <name> — 启用用户", func(a []string) error { return cmdUserDisabled(a, false) }},
	{"mauseroff", "mauseroff <name> — 禁用用户", func(a []string) error { return cmdUserDisabled(a, true) }},
	{"mauserpw", "mauserpw <name> [-e 口令环境变量] — 重置口令", cmdUserPassword},
	// 审计对象
	{"maassetls", "maassetls [-k 类型] [-j] — 资产列表", cmdAssetList},
	{"maassetadd", "maassetadd <类型> <端点> [-i id] [-n 名称] [-u 账号] [-h 医院] [-f labels文件] — 登记资产", cmdAssetAdd},
	{"maassetshow", "maassetshow <id> — 资产详情", cmdAssetShow},
	{"maassetmod", "maassetmod <id> [端点] [-n 名称] [-u 账号] [-f labels文件] — 修改资产", cmdAssetMod},
	{"maassetrm", "maassetrm <id> — 删除资产登记（历史包保留）", cmdAssetDelete},
	// 审计执行与评估
	{"maaudit", "maaudit <资产id> [-b 基线] [-e 口令环境变量] — 一键审计（按类型自动分发）；maaudit -f 清单.yaml 批量", cmdAudit},
	{"maeval", "maeval <包id> [-b 基线] [-F] — 在线评估", cmdEvaluate},
	{"maoffeval", "maoffeval <包.zip> [-b 基线.json] [-o 报告.docx] [-j] [-F] — 离线评估（不依赖服务端）", cmdOffEval},
	// 事实包
	{"mabundlels", "mabundlels [-a 资产] [-j] — 事实包列表", cmdBundleList},
	{"mabundlein", "mabundlein <文件.zip> — 导入事实包", cmdBundleImport},
	{"mabundleshow", "mabundleshow <包id> [-j] — 包元数据/收据/事实构成", cmdBundleShow},
	{"mabundledrift", "mabundledrift <新包> <旧包> — 漂移对比", cmdBundleDrift},
	{"mabundleeff", "mabundleeff <包id> [-j] — 有效权限", cmdBundleEffective},
	// 问题与报告
	{"mafind", "mafind <包id> [-c 结论] [-r 规则] [-j] [-o 清单.csv] — 问题清单", cmdFindings},
	{"mareport", "mareport <包id> [-o 报告.docx] — 生成报告并下载 Word", cmdReport},
	{"mareportls", "mareportls — 报告列表", cmdReportList},
	{"mareportshow", "mareportshow <报告id> [-j] — 报告摘要", cmdReportShow},
	{"mareportfix", "mareportfix <报告id> [-r 规则] — 修复/回滚脚本", cmdReportScripts},
	// 基线与规则
	{"mabasels", "mabasels [-h 医院] [-j] — 基线列表", cmdBaselineList},
	{"mabaseshow", "mabaseshow <id> [-o 文件] — 查看/导出基线", cmdBaselineGet},
	{"mabaseadd", "mabaseadd -f 基线.json — 登记基线（文件）", cmdBaselineApply},
	{"mabasediff", "mabasediff <基线A> <基线B> — 放行集差异（ID 或 .json 文件）", cmdBaselineDiff},
	{"mabaseexempt", "mabaseexempt <finding-id> [-b 基线] [-y] [原因…] — 一键把问题加入基线", cmdBaselineExempt},
	{"marulels", "marulels [-j] — 规则与本站启停状态", cmdRuleList},
	{"maruleoff", "maruleoff <规则id> <原因…> — 关闭检查项（本站）", func(a []string) error { return cmdRuleSet(a, false) }},
	{"maruleon", "maruleon <规则id> — 恢复检查项", func(a []string) error { return cmdRuleSet(a, true) }},
	// 关联、汇总、服务端
	{"macorr", "macorr [包id…] — 跨包提权路径（缺省取各资产最新包）", cmdCorrelate},
	{"masum", "masum — 医院风险汇总", cmdSummary},
	{"masrv", "masrv — 服务端状态", cmdServerStatus},
	{"masrvbak", "masrvbak <备份文件> — 平台库在线备份", cmdServerBackup},
}

var commands = func() map[string]func([]string) error {
	m := map[string]func([]string) error{}
	for _, c := range cmdList {
		m[c.name] = c.fn
	}
	return m
}()

func printIndex() {
	fmt.Fprintf(os.Stderr, "ma — MedAudit 工程师命令行 %s（LVM 风格命令族）\n\n", version)
	fmt.Fprintln(os.Stderr, "调用：<命令名> [短旗标] <位置参数…>，或 ma <命令> …；全局 -s <url> 指定服务端。")
	fmt.Fprintln(os.Stderr, "上下文（服务端/用户/当前医院）存 ~/.medaudit/session.json，用 mause 切换医院。\n")
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

func main() {
	args := os.Args[1:]
	for len(args) >= 2 && args[0] == "-s" {
		flagServer = args[1]
		args = args[2:]
	}
	invoked := filepath.Base(os.Args[0])
	var fn func([]string) error
	if f, ok := commands[invoked]; ok {
		fn = f
	} else {
		// ma 分发器形式：ma <命令>（命令名可带或不带 ma 前缀）
		if len(args) == 0 {
			printIndex()
			return
		}
		name := args[0]
		if name == "version" {
			fmt.Println("ma", version)
			return
		}
		if f, ok := commands[name]; ok {
			fn = f
		} else if f, ok := commands["ma"+name]; ok {
			fn = f
		} else if f, ok := commands["ma"+strings.TrimPrefix(name, "ma")]; ok {
			fn = f
		}
		if fn == nil {
			fmt.Fprintf(os.Stderr, "未知命令 %q\n\n", name)
			printIndex()
			os.Exit(1)
		}
		args = args[1:]
	}
	if err := fn(args); err != nil {
		if ee, ok := err.(*exitError); ok {
			fmt.Fprintln(os.Stderr, "错误：", ee.msg)
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "错误：", err)
		os.Exit(1)
	}
}
