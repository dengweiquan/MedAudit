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
