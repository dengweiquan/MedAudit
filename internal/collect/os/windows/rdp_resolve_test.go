package windows

import (
	"errors"
	"testing"
)

var errDenied = errors.New("access denied")

// 组策略读取被拒时不得无声回退到本地配置：必须返回错误。
func TestResolveRDPSettingsPolicyDenied(t *testing.T) {
	_, err := ResolveRDPSettingsRaw(
		RegRead{Err: errDenied},                               // 组策略拒绝访问
		RegRead{Value: RDPValue{Value: false, Present: true}}, // 本地允许连接
		RegRead{Err: errDenied},                               // 组策略 NLA 拒绝访问
		RegRead{Value: RDPValue{Value: true, Present: true}},  // 本地要求 NLA
	)
	if err == nil {
		t.Fatal("want error for denied group-policy read, got nil (silent fallback)")
	}
}

// 组策略明确未配置时才回退本地。
func TestResolveRDPSettingsPolicyAbsent(t *testing.T) {
	s, err := ResolveRDPSettingsRaw(
		RegRead{}, // 组策略未配置
		RegRead{Value: RDPValue{Value: false, Present: true}}, // 本地允许连接
		RegRead{}, // 组策略未配置
		RegRead{Value: RDPValue{Value: false, Present: true}}, // 本地不要求 NLA
	)
	if err != nil {
		t.Fatalf("want no error, got %v", err)
	}
	if !s.Enabled.Present || !s.Enabled.Value || s.EnabledSource != "local" {
		t.Fatalf("want local enabled, got %+v", s.Enabled)
	}
	if !s.NLA.Present || s.NLA.Value || s.NLASource != "local" {
		t.Fatalf("want local nla=false, got %+v", s.NLA)
	}
}

// 组策略存在时优先，不读本地值的结果。
func TestResolveRDPSettingsPolicyWins(t *testing.T) {
	s, err := ResolveRDPSettingsRaw(
		RegRead{Value: RDPValue{Value: true, Present: true}},  // 组策略拒绝连接
		RegRead{Value: RDPValue{Value: false, Present: true}}, // 本地允许连接
		RegRead{Value: RDPValue{Value: true, Present: true}},  // 组策略要求 NLA
		RegRead{Value: RDPValue{Value: false, Present: true}}, // 本地不要求 NLA
	)
	if err != nil {
		t.Fatalf("want no error, got %v", err)
	}
	if !s.Enabled.Present || s.Enabled.Value || s.EnabledSource != "group-policy" {
		t.Fatalf("want policy disabled, got %+v", s.Enabled)
	}
	if !s.NLA.Present || !s.NLA.Value || s.NLASource != "group-policy" {
		t.Fatalf("want policy nla=true, got %+v", s.NLA)
	}
}
