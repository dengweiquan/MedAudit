package facts

import (
	"strings"
	"testing"
)

// 负向测试：秘密值不得原样出现在脱敏结果中。
func TestRedactSecrets(t *testing.T) {
	cases := []struct{ in, secret string }{
		{`login failed for user 'sa': password=Hunter2!`, "Hunter2!"},
		{`could not connect: pwd=MyPwd123`, "MyPwd123"},
		{`auth failed: token=eyJhbGciOiJIUzI1NiJ9`, "eyJhbGciOiJIUzI1NiJ9"},
		{`dial sqlserver://sa:P@ssw0rd@127.0.0.1:1433`, "P@ssw0rd"},
		{`Authorization: Bearer abcdef123456`, "abcdef123456"},
		{`api_key=AKIAIOSFODNN7EXAMPLE`, "AKIAIOSFODNN7EXAMPLE"},
	}
	for _, tc := range cases {
		got := RedactSecrets(tc.in)
		if strings.Contains(got, tc.secret) {
			t.Errorf("secret leaked: in=%q got=%q", tc.in, got)
		}
		if !strings.Contains(got, "***") {
			t.Errorf("no redaction marker: in=%q got=%q", tc.in, got)
		}
	}
	// 良性文本不变。
	benign := `open /etc/sshd_config: permission denied`
	if got := RedactSecrets(benign); got != benign {
		t.Errorf("benign changed: %q", got)
	}
	if got := RedactSecrets(""); got != "" {
		t.Errorf("empty changed: %q", got)
	}
}
