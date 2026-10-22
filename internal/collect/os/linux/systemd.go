package linux

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
)

// UnitInfo systemd 单元的白名单属性（只读，不含环境变量与完整启停脚本）。
type UnitInfo struct {
	ID          string
	ActiveState string
	SubState    string
	UnitType    string
	User        string // 配置的运行用户（systemd.exec User=）
	Group       string
	MainPID     int
	ExecMainPID int
	FragmentPath string // 单元文件路径
}

// unitProps 允许查询的 systemctl 属性白名单。
var unitProps = []string{
	"Id", "ActiveState", "SubState", "Type",
	"User", "Group", "MainPID", "ExecMainPID", "FragmentPath",
}

// ReadUnit 用 systemctl show 读取单元白名单属性。
// 直接 exec，无 shell；属性名固定，不接受外部输入拼接。
func ReadUnit(ctx context.Context, unit string) (*UnitInfo, error) {
	// 单元名做基本校验，防止参数注入。
	if strings.ContainsAny(unit, ";|&$`'\"\\\n") {
		return nil, &UnitError{Unit: unit, Msg: "非法单元名"}
	}
	args := append([]string{"show", unit, "--no-pager"}, propArgs()...)
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, &UnitError{Unit: unit, Msg: "systemctl show 失败: " + err.Error()}
	}
	u := &UnitInfo{}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "Id":
			u.ID = v
		case "ActiveState":
			u.ActiveState = v
		case "SubState":
			u.SubState = v
		case "Type":
			u.UnitType = v
		case "User":
			u.User = v
		case "Group":
			u.Group = v
		case "MainPID":
			u.MainPID, _ = strconv.Atoi(v)
		case "ExecMainPID":
			u.ExecMainPID, _ = strconv.Atoi(v)
		case "FragmentPath":
			u.FragmentPath = v
		}
	}
	if u.ID == "" {
		return nil, &UnitError{Unit: unit, Msg: "单元不存在或无权读取"}
	}
	return u, nil
}

func propArgs() []string {
	var args []string
	for _, p := range unitProps {
		args = append(args, "-p", p)
	}
	return args
}

// UnitError 单元读取错误。
type UnitError struct {
	Unit string
	Msg  string
}

func (e *UnitError) Error() string { return "unit " + e.Unit + ": " + e.Msg }

// RunningServices 枚举运行中的 systemd 服务单元（M19 缺省服务覆盖）。
// systemctl 不可用/无输出时返回 nil（调用方回退为仅基础采集，相关检查
// 保持诚实 UNKNOWN，不假装覆盖）。上限 50 个防失控。
func RunningServices(ctx context.Context) []string {
	cmd := exec.CommandContext(ctx, "systemctl",
		"list-units", "--type=service", "--state=running", "--no-legend", "--no-pager", "--plain")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parseRunningUnits(string(out))
}

// parseRunningUnits 解析 list-units --plain 输出：每行首字段为单元名。
func parseRunningUnits(out string) []string {
	var units []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if !strings.HasSuffix(name, ".service") {
			continue
		}
		if strings.ContainsAny(name, ";|&$`'\"\\") {
			continue
		}
		units = append(units, name)
		if len(units) >= 50 {
			break
		}
	}
	return units
}
