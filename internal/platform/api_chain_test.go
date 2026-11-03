package platform

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"medaudit/internal/apiaudit"
	"medaudit/internal/facts"
	"medaudit/internal/rules"
)

// 全链回归（静态复核二轮第 1 项）：Run（引擎实测）→ ToFacts（身份标记）→
// 规则评估 → 合规判定。只配置 admin 与普通用户、无匿名身份时，普通用户在
// 管理员端点的 403 不得被当作匿名探针：未认证规则 UNKNOWN，合规条款 unknown；
// 配齐匿名身份后，匿名拒答 + 已认证对照 → 未认证 PASS，条款 pass。
func TestAPIChainNoAnonUnknown(t *testing.T) {
	rep := runChainFixture(t, false)
	assertChainAnon(t, rep, facts.ConclusionUnknown, "unknown")
}

func TestAPIChainWithAnonPass(t *testing.T) {
	rep := runChainFixture(t, true)
	assertChainAnon(t, rep, facts.ConclusionPass, "pass")
}

func runChainFixture(t *testing.T, withAnon bool) *apiaudit.Report {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.Header.Get("X-User")
		switch r.URL.Path {
		case "/api/profile":
			if user == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Write([]byte(`{"user":"` + user + `"}`))
		case "/api/admin/users":
			switch user {
			case "admin":
				w.Write([]byte(`[{"user":"admin"}]`))
			case "":
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			default:
				http.Error(w, "forbidden", http.StatusForbidden)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	spec := filepath.Join(t.TempDir(), "openapi.json")
	if err := os.WriteFile(spec, []byte(`{"openapi":"3.0.3","paths":{
		"/api/profile":{"get":{}},
		"/api/admin/users":{"get":{}}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ids := []apiaudit.Identity{
		{Name: "admin", Role: "admin", Headers: map[string]string{"X-User": "admin"}},
		{Name: "user", Role: "user", Headers: map[string]string{"X-User": "user"}},
	}
	if withAnon {
		ids = append([]apiaudit.Identity{{Name: "anon"}}, ids...)
	}
	cfg := &apiaudit.Config{
		BaseURL:       srv.URL,
		SpecFile:      spec,
		Identities:    ids,
		TimeoutSecond: 10,
		HospitalID:    "h1",
		AssetID:       "a1",
		Expectations: []apiaudit.Expectation{
			{Method: "GET", Path: "/api/profile", Access: apiaudit.AccessAuthenticated},
			{Method: "GET", Path: "/api/admin/users", Access: apiaudit.AccessAdminOnly},
		},
	}
	rep, err := apiaudit.Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func assertChainAnon(t *testing.T, rep *apiaudit.Report, wantRule facts.Conclusion, wantClause string) {
	t.Helper()
	bundle := &facts.FactBundle{
		Collector: facts.CollectorInfo{Adapter: facts.TargetAPI},
		Facts:     apiaudit.ToFacts(rep),
	}
	var gotRule facts.Conclusion
	found := false
	for _, r := range rules.DefaultRegistry().Evaluate(bundle, &rules.Baseline{}) {
		if r.RuleID == "api.anon_protected_access" {
			gotRule, found = r.Conclusion, true
		}
	}
	if !found {
		t.Fatal("未认证规则无评估结果")
	}
	if gotRule != wantRule {
		t.Fatalf("未认证规则：want %s, got %s（报告身份 %v）", wantRule, gotRule, rep.Identities)
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	res, err := APICompliance(raw, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Clause.Status != wantClause {
		t.Fatalf("合规条款：want %s, got %s（note=%q）", wantClause, res.Clause.Status, res.Note)
	}
}
