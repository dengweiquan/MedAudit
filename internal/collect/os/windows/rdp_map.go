package windows

// RDPValue 注册表读值：Present=false 表示键不存在或不可读（不得默认为安全）。
type RDPValue struct {
	Value   bool
	Present bool
}

// ResolveRDPValue 策略优先：策略键存在时取策略值，否则取本地值；两者皆无则 Present=false。
func ResolveRDPValue(policy, local RDPValue) RDPValue {
	if policy.Present {
		return policy
	}
	return local
}

// RDPSettings RDP 有效配置（策略/本地已折叠后的最终值 + 来源标注）。
type RDPSettings struct {
	Enabled       RDPValue
	EnabledSource string // "group-policy" | "local" | ""（无值时）
	NLA           RDPValue
	NLASource     string
}

// RDPAttributes 把有效配置映射为事实属性：缺失项不写属性，规则门控据此判 UNKNOWN。
// enabled/nla 的布尔值写 "true"/"false"；来源写 enabled_source / nla_source。
// RegRead 一次注册表读取的结果：Value（Present=false 表示键/值不存在，即未配置）
// 或读取错误（拒绝访问等）。Present=false 与 Err!=nil 是两种不同状态，不得混淆。
type RegRead struct {
	Value RDPValue
	Err   error
}

// ResolveRDPSettingsRaw 由原始读取结果解析 RDP 有效配置（纯函数，可单测）：
// 组策略读取出错时直接返回错误，绝不无声回退到本地配置；只有组策略明确未配置
// （无错误且 Present=false）时才用本地值。本地读取出错同样返回错误（不猜测）。
func ResolveRDPSettingsRaw(polDeny, locDeny, polNLA, locNLA RegRead) (RDPSettings, error) {
	for _, r := range []RegRead{polDeny, locDeny, polNLA, locNLA} {
		if r.Err != nil {
			return RDPSettings{}, r.Err
		}
	}
	var s RDPSettings
	if deny := ResolveRDPValue(polDeny.Value, locDeny.Value); deny.Present {
		s.Enabled = RDPValue{Value: !deny.Value, Present: true}
		if polDeny.Value.Present {
			s.EnabledSource = "group-policy"
		} else {
			s.EnabledSource = "local"
		}
	}
	s.NLA = ResolveRDPValue(polNLA.Value, locNLA.Value)
	if s.NLA.Present {
		if polNLA.Value.Present {
			s.NLASource = "group-policy"
		} else {
			s.NLASource = "local"
		}
	}
	return s, nil
}

func RDPAttributes(s RDPSettings) map[string]string {
	attrs := map[string]string{}
	if s.Enabled.Present {
		attrs["enabled"] = boolStr(s.Enabled.Value)
		attrs["enabled_source"] = s.EnabledSource
	}
	if s.NLA.Present {
		attrs["nla"] = boolStr(s.NLA.Value)
		attrs["nla_source"] = s.NLASource
	}
	return attrs
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
