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

// 静态复核回归：NetSetupJoinStatus 微软定义为 0 未知、1 未加入、2 工作组、3 域
// （旧代码误把 1 当工作组、2 当域、3 当未知，导致域成员被标为未知覆盖范围）。
func TestJoinStatusToRole(t *testing.T) {
	cases := []struct {
		status uint32
		isDC   bool
		want   string
	}{
		{0, false, "unknown"},
		{1, false, "unjoined"},
		{2, false, "workgroup"},
		{3, false, "domain-member"},
		{3, true, "domain-controller"},
		{1, true, "domain-controller"},
		{99, false, "unknown"},
	}
	for _, tc := range cases {
		if got := joinStatusToRole(tc.status, tc.isDC); got != tc.want {
			t.Errorf("status %d isDC=%v: want %q, got %q", tc.status, tc.isDC, tc.want, got)
		}
	}
	if got := passwordScopeForRole("unjoined"); got != "local-sam" {
		t.Errorf("unjoined scope: want local-sam, got %q", got)
	}
}
