package windows

import "testing"

func TestResolveRDPValue(t *testing.T) {
	policy := RDPValue{Value: false, Present: true}
	local := RDPValue{Value: true, Present: true}
	if got := ResolveRDPValue(policy, local); !got.Present || got.Value {
		t.Fatalf("策略存在时应取策略值 false，实际 %+v", got)
	}
	if got := ResolveRDPValue(RDPValue{}, local); !got.Present || !got.Value {
		t.Fatalf("策略缺失时应取本地值 true，实际 %+v", got)
	}
	if got := ResolveRDPValue(RDPValue{}, RDPValue{}); got.Present {
		t.Fatalf("两者皆无时应为 Present=false，实际 %+v", got)
	}
}

func TestRDPAttributes(t *testing.T) {
	s := RDPSettings{
		Enabled:       RDPValue{Value: true, Present: true},
		EnabledSource: "group-policy",
		NLA:           RDPValue{},
	}
	attrs := RDPAttributes(s)
	if attrs["enabled"] != "true" || attrs["enabled_source"] != "group-policy" {
		t.Fatalf("enabled 属性错误：%v", attrs)
	}
	if _, ok := attrs["nla"]; ok {
		t.Fatalf("NLA 缺失时不应写 nla 属性：%v", attrs)
	}
}

func TestPasswordPolicyAttributes(t *testing.T) {
	p := PasswordPolicy{
		Scope: "local-sam", MinLength: 7, MaxAgeSec: TimeqForever,
		LockoutThreshold: 0,
	}
	attrs := PasswordPolicyAttributes(p)
	if attrs["scope"] != "local-sam" || attrs["min_password_length"] != "7" {
		t.Fatalf("属性错误：%v", attrs)
	}
	if attrs["max_password_age_sec"] != "4294967295" {
		t.Fatalf("TIMEQ_FOREVER 应原样输出 4294967295，实际 %v", attrs["max_password_age_sec"])
	}
	if attrs["lockout_threshold"] != "0" {
		t.Fatalf("lockout_threshold 应为 0，实际 %v", attrs["lockout_threshold"])
	}
}
