package rules

import (
	"testing"

	"medaudit/internal/facts"
)

func winPwdFact(attrs map[string]string) facts.Fact {
	return facts.Fact{FactID: "f-pwd", Kind: facts.FactAccountConfig, Subject: "password-policy",
		Status: facts.StatusObserved, Source: "win.password_policy", Attributes: attrs}
}

func winPwdBundle(attrs map[string]string, status string) *facts.FactBundle {
	return testBundleR(facts.TargetOSWindows, []facts.Fact{winPwdFact(attrs)},
		[]facts.Receipt{{TemplateID: "win.password_policy", TemplateVersion: "1", Status: status}})
}

func TestWinPasswordMinLength(t *testing.T) {
	short := winPwdBundle(map[string]string{"scope": "local-sam", "min_password_length": "7"}, "ok")
	r := singleResult(t, short, &Baseline{}, "os.windows.password_min_length")
	expectConclusion(t, r, facts.ConclusionFail)

	ok := winPwdBundle(map[string]string{"scope": "local-sam", "min_password_length": "8"}, "ok")
	r = singleResult(t, ok, &Baseline{}, "os.windows.password_min_length")
	expectConclusion(t, r, facts.ConclusionPass)

	noReceipt := testBundleR(facts.TargetOSWindows, []facts.Fact{winPwdFact(
		map[string]string{"scope": "local-sam", "min_password_length": "7"})}, nil)
	r = singleResult(t, noReceipt, &Baseline{}, "os.windows.password_min_length")
	expectConclusion(t, r, facts.ConclusionUnknown)
}

func TestWinPasswordMaxAgeNever(t *testing.T) {
	never := winPwdBundle(map[string]string{"scope": "local-sam", "max_password_age_sec": "4294967295"}, "ok")
	r := singleResult(t, never, &Baseline{}, "os.windows.password_max_age_never")
	expectConclusion(t, r, facts.ConclusionFail)

	limited := winPwdBundle(map[string]string{"scope": "local-sam", "max_password_age_sec": "7776000"}, "ok")
	r = singleResult(t, limited, &Baseline{}, "os.windows.password_max_age_never")
	expectConclusion(t, r, facts.ConclusionPass)
}

func TestWinPasswordLockout(t *testing.T) {
	off := winPwdBundle(map[string]string{"scope": "domain-default", "lockout_threshold": "0"}, "ok")
	r := singleResult(t, off, &Baseline{}, "os.windows.password_lockout_disabled")
	expectConclusion(t, r, facts.ConclusionFail)

	on := winPwdBundle(map[string]string{"scope": "domain-default", "lockout_threshold": "5"}, "ok")
	r = singleResult(t, on, &Baseline{}, "os.windows.password_lockout_disabled")
	expectConclusion(t, r, facts.ConclusionPass)
}

func TestWinPasswordComplexity(t *testing.T) {
	sec := func(attrs map[string]string, status string) *facts.FactBundle {
		return testBundleR(facts.TargetOSWindows, []facts.Fact{{
			FactID: "f-sec", Kind: facts.FactAccountConfig, Subject: "password-policy",
			Status: facts.StatusObserved, Source: "win.secedit", Attributes: attrs,
		}}, []facts.Receipt{{TemplateID: "win.secedit", TemplateVersion: "1", Status: status}})
	}
	off := sec(map[string]string{"scope": "local-sam", "password_complexity": "0"}, "ok")
	r := singleResult(t, off, &Baseline{}, "os.windows.password_complexity_off")
	expectConclusion(t, r, facts.ConclusionFail)

	on := sec(map[string]string{"scope": "local-sam", "password_complexity": "1"}, "ok")
	r = singleResult(t, on, &Baseline{}, "os.windows.password_complexity_off")
	expectConclusion(t, r, facts.ConclusionPass)

	// secedit 导出失败 → UNKNOWN（不默认为安全）
	failed := sec(map[string]string{"scope": "local-sam"}, "failed")
	r = singleResult(t, failed, &Baseline{}, "os.windows.password_complexity_off")
	expectConclusion(t, r, facts.ConclusionUnknown)

	// 导出成功但无复杂度键 → UNKNOWN
	noKey := sec(map[string]string{"scope": "local-sam"}, "ok")
	r = singleResult(t, noKey, &Baseline{}, "os.windows.password_complexity_off")
	expectConclusion(t, r, facts.ConclusionUnknown)
}

func TestWinRDPNLA(t *testing.T) {
	rdp := func(attrs map[string]string, status string) *facts.FactBundle {
		return testBundleR(facts.TargetOSWindows, []facts.Fact{{
			FactID: "f-rdp", Kind: facts.FactAccountConfig, Subject: "rdp",
			Status: facts.StatusObserved, Source: "win.rdp", Attributes: attrs,
		}}, []facts.Receipt{{TemplateID: "win.rdp", TemplateVersion: "1", Status: status}})
	}
	off := rdp(map[string]string{"enabled": "true", "enabled_source": "local", "nla": "false", "nla_source": "local"}, "ok")
	r := singleResult(t, off, &Baseline{}, "os.windows.rdp_nla_disabled")
	expectConclusion(t, r, facts.ConclusionFail)

	on := rdp(map[string]string{"enabled": "true", "enabled_source": "group-policy", "nla": "true", "nla_source": "group-policy"}, "ok")
	r = singleResult(t, on, &Baseline{}, "os.windows.rdp_nla_disabled")
	expectConclusion(t, r, facts.ConclusionPass)

	// RDP 关闭 → 不适用（不是 PASS）
	closed := rdp(map[string]string{"enabled": "false", "enabled_source": "local"}, "ok")
	r = singleResult(t, closed, &Baseline{}, "os.windows.rdp_nla_disabled")
	expectConclusion(t, r, facts.ConclusionNotApplicable)

	// RDP 开启但 NLA 未读到 → UNKNOWN
	noNLA := rdp(map[string]string{"enabled": "true", "enabled_source": "local"}, "ok")
	r = singleResult(t, noNLA, &Baseline{}, "os.windows.rdp_nla_disabled")
	expectConclusion(t, r, facts.ConclusionUnknown)

	// 注册表不可读（收据失败）→ UNKNOWN
	failed := rdp(map[string]string{"enabled": "true", "nla": "false"}, "failed")
	r = singleResult(t, failed, &Baseline{}, "os.windows.rdp_nla_disabled")
	expectConclusion(t, r, facts.ConclusionUnknown)
}

// 豁免按 scope 区分：local-sam 的豁免不覆盖 domain-default 的事实。
func TestWinPasswordBaselineScope(t *testing.T) {
	b := winPwdBundle(map[string]string{"scope": "local-sam", "min_password_length": "7"}, "ok")
	localAllow := &Baseline{Allows: []BaselineAllow{
		{Subject: "password-policy", Kind: "policy", Value: "min_length", Scope: "local-sam"},
	}}
	r := singleResult(t, b, localAllow, "os.windows.password_min_length")
	expectConclusion(t, r, facts.ConclusionPass)

	domainAllow := &Baseline{Allows: []BaselineAllow{
		{Subject: "password-policy", Kind: "policy", Value: "min_length", Scope: "domain-default"},
	}}
	r = singleResult(t, b, domainAllow, "os.windows.password_min_length")
	expectConclusion(t, r, facts.ConclusionFail)
}
