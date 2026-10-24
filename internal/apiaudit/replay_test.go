package apiaudit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture 目标：按 Cookie session 值返回不同状态，模拟会话失效与否。
func replayFixture(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/boom") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		c, err := r.Cookie("session")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch c.Value {
		case "tok-valid":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"user":"alice"}`))
		case "tok-logged-out", "tok-expired":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
}

const replaySpec = `{"openapi":"3.0.0","paths":{"/api/me":{"get":{}},"/api/users/{user_id}":{"get":{}},"/api/boom":{"get":{}},"/api/admin":{"post":{}}}}`

func replayConfig(t *testing.T, srv *httptest.Server, replayYAML string) *Config {
	t.Helper()
	specPath := filepath.Join(t.TempDir(), "spec.json")
	if err := os.WriteFile(specPath, []byte(replaySpec), 0600); err != nil {
		t.Fatal(err)
	}
	yamlText := `base_url: "` + srv.URL + `"
spec_file: "` + specPath + `"
identities:
  - name: alice
    role: user
    headers: {Cookie: "session=tok-logged-out"}
    owns: {user_id: "2"}
  - name: bob
    role: user
    headers: {Cookie: "session=tok-valid"}
    owns: {user_id: "3"}
expectations:
  - {method: GET, path: "/api/me", access: authenticated}
  - {method: GET, path: "/api/users/{user_id}", access: owner_or_admin}
  - {method: GET, path: "/api/boom", access: authenticated}
  - {method: POST, path: "/api/admin", access: admin_only}
` + replayYAML
	cfgPath := filepath.Join(t.TempDir(), "cfg.yml")
	if err := os.WriteFile(cfgPath, []byte(yamlText), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func findReplay(t *testing.T, rep *Report, identity, endpoint string) Check {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Identity == identity && c.Endpoint == endpoint && strings.HasPrefix(c.Probe, "replay:") {
			return c
		}
	}
	t.Fatalf("未找到重放检查 %s %s，全部检查：%+v", identity, endpoint, rep.Checks)
	return Check{}
}

func TestReplay(t *testing.T) {
	srv := replayFixture(t)
	defer srv.Close()
	cfg := replayConfig(t, srv, `replay:
  sessions:
    - {name: alice-logged-out, identity: alice, invalidated: logged_out, note: "登出后捕获"}
    - {name: bob-expired, identity: bob, invalidated: expired}
`)
	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	// 登出会话被拒 -> PASS
	if c := findReplay(t, rep, "alice-logged-out", "GET /api/me"); c.Conclusion != ConclPass {
		t.Errorf("登出重放期望 PASS，得到 %s (%s)", c.Conclusion, c.Detail)
	}
	// 过期名义但凭证仍有效 -> FAIL
	if c := findReplay(t, rep, "bob-expired", "GET /api/me"); c.Conclusion != ConclFail {
		t.Errorf("过期重放期望 FAIL，得到 %s (%s)", c.Conclusion, c.Detail)
	}
	// 目标 500 -> UNKNOWN
	if c := findReplay(t, rep, "alice-logged-out", "GET /api/boom"); c.Conclusion != ConclUnknown {
		t.Errorf("500 目标期望 UNKNOWN，得到 %s", c.Conclusion)
	}
	// 写方法默认 NOT_RUN（endpoints 显式含写方法时才登记）
	cfgW := replayConfig(t, srv, `replay:
  sessions:
    - {name: alice-logged-out, identity: alice, invalidated: logged_out}
  endpoints: ["GET /api/me", "POST /api/admin"]
`)
	repW, err := Run(context.Background(), cfgW)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range repW.Checks {
		if c.Endpoint == "POST /api/admin" && strings.HasPrefix(c.Probe, "replay:") {
			found = true
			if c.Conclusion != ConclNotRun {
				t.Errorf("写方法重放期望 NOT_RUN，得到 %s", c.Conclusion)
			}
		}
	}
	if !found {
		t.Errorf("未找到写方法重放检查")
	}
	// 无 replay 段时行为不变：不产生任何 replay 检查
	cfg2 := replayConfig(t, srv, ``)
	rep2, err := Run(context.Background(), cfg2)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rep2.Checks {
		if strings.HasPrefix(c.Probe, "replay:") {
			t.Errorf("无 replay 配置却产生重放检查：%+v", c)
		}
	}
}

func TestReplayConfigValidation(t *testing.T) {
	srv := replayFixture(t)
	defer srv.Close()
	bad := []string{
		`replay:
  sessions:
    - {name: x, identity: nobody, invalidated: logged_out}
`,
		`replay:
  sessions:
    - {name: x, identity: alice, invalidated: bogus}
`,
		`replay:
  sessions:
    - {name: x, identity: alice, invalidated: logged_out}
  endpoints: ["GET nope"]
`,
	}
	for i, y := range bad {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("用例 %d 不应 panic：%v", i, r)
				}
			}()
			specPath := filepath.Join(t.TempDir(), "spec.json")
			_ = os.WriteFile(specPath, []byte(replaySpec), 0600)
			cfgPath := filepath.Join(t.TempDir(), "cfg.yml")
			_ = os.WriteFile(cfgPath, []byte(`base_url: "`+srv.URL+`"
spec_file: "`+specPath+`"
identities:
  - {name: alice, headers: {Cookie: "session=tok-valid"}}
`+y), 0600)
			if _, err := LoadConfig(cfgPath); err == nil {
				t.Errorf("用例 %d 期望校验失败，实际通过", i)
			}
		}()
	}
}
