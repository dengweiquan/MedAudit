package windows

import "testing"

// 三态角色 → 覆盖范围：工作组与域成员均为本地 SAM（域成员本机查询不等于域默认策略），
// 只有域控为域默认；角色未知时不猜测。
func TestPasswordScopeForRole(t *testing.T) {
	cases := map[string]string{
		"workgroup":         "local-sam",
		"domain-member":     "local-sam",
		"domain-controller": "domain-default",
		"unknown":           "unknown",
		"":                  "unknown",
	}
	for role, want := range cases {
		if got := passwordScopeForRole(role); got != want {
			t.Errorf("role %q: want %q, got %q", role, want, got)
		}
	}
}

func TestPasswordPolicyAttributesRole(t *testing.T) {
	attrs := PasswordPolicyAttributes(PasswordPolicy{Scope: "local-sam", Role: "domain-member", MinLength: 7})
	if attrs["scope"] != "local-sam" || attrs["machine_role"] != "domain-member" {
		t.Fatalf("attrs: %+v", attrs)
	}
}
