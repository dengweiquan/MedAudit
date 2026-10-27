// M37-3.1：服务端接口 httptest 覆盖。每个用例起一个真实 httptest 服务
// （临时 SQLite 库 + 与 main 相同的鉴权/操作日志中间件链），只覆盖
// 3.1 方案列出的接口：登录、未登录拦截、操作日志、告警确认、
// 定期复检、模板套用。
package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"medaudit/internal/platform"
	"medaudit/internal/rules"
)

type testServer struct {
	srv      *httptest.Server
	db       *sql.DB
	sessions *platform.SessionStore
	client   *http.Client
}

func newTestServer(t *testing.T, kr *platform.EvidenceKeyring) *testServer {
	t.Helper()
	db, err := platform.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := platform.Migrate(db); err != nil {
		t.Fatalf("测试库迁移失败: %v", err)
	}
	if err := platform.SeedDefaultAdmin(db); err != nil {
		t.Fatalf("播种默认管理员失败: %v", err)
	}
	sessions := platform.NewSessionStore()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok", "version": version})
	})
	// 与 main 相同的备份下载入口（仅用于验证“下载记一条”）。
	mux.HandleFunc("/api/v1/admin/backup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path, err := platform.BackupSnapshot(db, os.TempDir())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer os.Remove(path)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=medaudit-platform-backup.db")
		http.ServeFile(w, r, path)
	})
	registerAuthRoutes(mux, db, sessions)
	registerOpLogRoutes(mux, db)
	registerAlertRoutes(mux, db, sessions)
	sched := platform.NewScheduler(db, rules.DefaultRegistry(), kr, "", "", "", platform.NewTokenStore())
	registerScheduleRoutes(mux, db, kr, sched, sessions)
	registerTemplateRoutes(mux, db, rules.DefaultRegistry(), sessions)
	registerAssetBundlesRoute(mux, db)
	srv := httptest.NewServer(opLogMiddleware(authMiddleware(mux, sessions), db, sessions))
	t.Cleanup(srv.Close)
	return &testServer{srv: srv, db: db, sessions: sessions, client: &http.Client{}}
}

func (s *testServer) do(t *testing.T, method, path string, body any, cookies []*http.Cookie) (int, []byte, *http.Response) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("序列化请求失败: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, s.srv.URL+path, rdr)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("请求 %s %s 失败: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读响应失败: %v", err)
	}
	return resp.StatusCode, data, resp
}

func (s *testServer) login(t *testing.T, username, password string) *http.Cookie {
	t.Helper()
	status, _, resp := s.do(t, http.MethodPost, "/api/v1/auth/login",
		map[string]string{"username": username, "password": password}, nil)
	if status != http.StatusOK {
		t.Fatalf("登录 %s 应 200，实际 %d", username, status)
	}
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	t.Fatal("登录响应未带会话 cookie")
	return nil
}

func opEntries(t *testing.T, db *sql.DB) []platform.OpEntry {
	t.Helper()
	items, _, err := platform.ListOpLog(db, 0, 1000)
	if err != nil {
		t.Fatalf("读操作日志失败: %v", err)
	}
	return items
}

func TestServerAuthLogin(t *testing.T) {
	s := newTestServer(t, nil)
	// 成功：200 + 会话 cookie。
	cookie := s.login(t, platform.DefaultAdminUser, platform.DefaultAdminPassword)
	if cookie == nil || cookie.Value == "" {
		t.Fatal("登录应返回非空会话 cookie")
	}
	// 失败：错口令与未知用户均为 401。
	for _, tc := range []struct{ user, pass string }{
		{platform.DefaultAdminUser, "wrong-password"},
		{"nobody", "whatever123"},
	} {
		status, _, _ := s.do(t, http.MethodPost, "/api/v1/auth/login",
			map[string]string{"username": tc.user, "password": tc.pass}, nil)
		if status != http.StatusUnauthorized {
			t.Errorf("登录 %s/%s 应 401，实际 %d", tc.user, tc.pass, status)
		}
	}
	// 令牌：经已登录会话铸造后，令牌登录应 200（铸造会吊销旧会话，之后重登口令）。
	status, data, _ := s.do(t, http.MethodPost, "/api/v1/auth/token", nil, []*http.Cookie{cookie})
	if status != http.StatusOK {
		t.Fatalf("铸造令牌应 200，实际 %d：%s", status, data)
	}
	var tokResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &tokResp); err != nil || tokResp.Token == "" {
		t.Fatalf("铸造令牌响应异常: %v %s", err, data)
	}
	status, data, _ = s.do(t, http.MethodPost, "/api/v1/auth/login",
		map[string]string{"token": tokResp.Token}, nil)
	if status != http.StatusOK {
		t.Fatalf("令牌登录应 200，实际 %d：%s", status, data)
	}
	if !strings.Contains(string(data), platform.DefaultAdminUser) {
		t.Errorf("令牌登录响应应含 admin，实际 %s", data)
	}
	status, _, _ = s.do(t, http.MethodPost, "/api/v1/auth/login",
		map[string]string{"token": "deadbeef"}, nil)
	if status != http.StatusUnauthorized {
		t.Errorf("无效令牌登录应 401，实际 %d", status)
	}
}

func TestServerAuthRequired(t *testing.T) {
	s := newTestServer(t, nil)
	// 未登录：受保护接口 401，健康检查与登录接口放行。
	if status, _, _ := s.do(t, http.MethodGet, "/api/v1/alerts", nil, nil); status != http.StatusUnauthorized {
		t.Errorf("未登录 GET /alerts 应 401，实际 %d", status)
	}
	if status, _, _ := s.do(t, http.MethodGet, "/api/v1/schedules", nil, nil); status != http.StatusUnauthorized {
		t.Errorf("未登录 GET /schedules 应 401，实际 %d", status)
	}
	if status, _, _ := s.do(t, http.MethodGet, "/api/v1/health", nil, nil); status != http.StatusOK {
		t.Errorf("未登录 GET /health 应 200，实际 %d", status)
	}
}

func TestServerOpLog(t *testing.T) {
	s := newTestServer(t, nil)
	cookie := s.login(t, platform.DefaultAdminUser, platform.DefaultAdminPassword)
	// 写操作记一条：改密（旧口令错误，400 也记）。
	if status, _, _ := s.do(t, http.MethodPost, "/api/v1/auth/change-password",
		map[string]string{"old_password": "wrong-old", "new_password": "NewPass123"}, []*http.Cookie{cookie}); status != http.StatusBadRequest {
		t.Fatalf("错旧口令改密应 400，实际 %d", status)
	}
	entries := opEntries(t, s.db)
	has := func(method, path string) bool {
		for _, e := range entries {
			if e.Method == method && e.Path == path {
				return true
			}
		}
		return false
	}
	if !has(http.MethodPost, "/api/v1/auth/login") {
		t.Error("操作日志应含登录 POST 条目")
	}
	if !has(http.MethodPost, "/api/v1/auth/change-password") {
		t.Error("操作日志应含改密 POST 条目")
	}
	// GET 不记：读告警前后条数不变。
	before := len(entries)
	if status, _, _ := s.do(t, http.MethodGet, "/api/v1/alerts", nil, []*http.Cookie{cookie}); status != http.StatusOK {
		t.Fatalf("读告警应 200，实际 %d", status)
	}
	if after := len(opEntries(t, s.db)); after != before {
		t.Errorf("GET 不应记操作日志：记前 %d 条，记后 %d 条", before, after)
	}
	// 下载记一条：备份下载（GET 但带 attachment）应落日志。
	status, _, resp := s.do(t, http.MethodGet, "/api/v1/admin/backup", nil, []*http.Cookie{cookie})
	if status != http.StatusOK {
		t.Fatalf("备份下载应 200，实际 %d", status)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("备份下载应带 attachment，实际 %q", resp.Header.Get("Content-Disposition"))
	}
	if !has(http.MethodGet, "/api/v1/admin/backup") {
		// has 闭包捕获的是旧 entries，重新查。
		found := false
		for _, e := range opEntries(t, s.db) {
			if e.Method == http.MethodGet && e.Path == "/api/v1/admin/backup" {
				found = true
			}
		}
		if !found {
			t.Error("操作日志应含备份下载 GET 条目")
		}
	}
	// 不含口令：全部条目字段均不得出现登录口令原文。
	for _, e := range opEntries(t, s.db) {
		for _, f := range []string{e.Actor, e.Method, e.Path, e.Note, e.ClientIP} {
			if strings.Contains(f, platform.DefaultAdminPassword) {
				t.Errorf("操作日志不得含口令原文：%+v", e)
			}
		}
	}
}

func TestServerAlerts(t *testing.T) {
	s := newTestServer(t, nil)
	a, err := platform.RecordAuditFailedAlert(s.db, "h-test", "a-mysql", "boom")
	if err != nil {
		t.Fatalf("写告警失败: %v", err)
	}
	cookie := s.login(t, platform.DefaultAdminUser, platform.DefaultAdminPassword)
	getAlerts := func(all bool) []platform.Alert {
		t.Helper()
		path := "/api/v1/alerts"
		if all {
			path += "?all=1"
		}
		status, data, _ := s.do(t, http.MethodGet, path, nil, []*http.Cookie{cookie})
		if status != http.StatusOK {
			t.Fatalf("读告警应 200，实际 %d：%s", status, data)
		}
		var items []platform.Alert
		if err := json.Unmarshal(data, &items); err != nil {
			t.Fatalf("解析告警失败: %v", err)
		}
		return items
	}
	contains := func(items []platform.Alert, id int64) bool {
		for _, it := range items {
			if it.ID == id {
				return true
			}
		}
		return false
	}
	if !contains(getAlerts(false), a.ID) {
		t.Fatalf("未确认列表应含告警 %d", a.ID)
	}
	status, _, _ := s.do(t, http.MethodPost, "/api/v1/alerts/"+strconv.FormatInt(a.ID, 10)+"/ack", nil, []*http.Cookie{cookie})
	if status != http.StatusOK {
		t.Fatalf("确认告警应 200，实际 %d", status)
	}
	if contains(getAlerts(false), a.ID) {
		t.Errorf("确认后未确认列表不应再含告警 %d", a.ID)
	}
	all := getAlerts(true)
	if !contains(all, a.ID) {
		t.Fatalf("all=1 列表应含已确认告警 %d", a.ID)
	}
	for _, it := range all {
		if it.ID == a.ID && it.AckedBy != platform.DefaultAdminUser {
			t.Errorf("已确认告警的确认人应为 admin，实际 %q", it.AckedBy)
		}
	}
}

func TestServerSchedulesNoKey(t *testing.T) {
	s := newTestServer(t, nil)
	cookie := s.login(t, platform.DefaultAdminUser, platform.DefaultAdminPassword)
	// 无证据密钥：PUT/DELETE/run 一律拒绝。
	if status, data, _ := s.do(t, http.MethodPut, "/api/v1/schedules/a-mysql",
		map[string]any{"cycle_days": 30, "password": "secret123"}, []*http.Cookie{cookie}); status != http.StatusBadRequest {
		t.Errorf("无密钥 PUT 应 400，实际 %d：%s", status, data)
	} else if !strings.Contains(string(data), "证据密钥") {
		t.Errorf("无密钥 PUT 应提示证据密钥，实际 %s", data)
	}
	if status, _, _ := s.do(t, http.MethodDelete, "/api/v1/schedules/a-mysql", nil, []*http.Cookie{cookie}); status != http.StatusBadRequest {
		t.Errorf("未开启 DELETE 应 400，实际 %d", status)
	}
	if status, _, _ := s.do(t, http.MethodPost, "/api/v1/schedules/a-mysql/run", nil, []*http.Cookie{cookie}); status != http.StatusBadRequest {
		t.Errorf("未开启 run 应 400，实际 %d", status)
	}
}

func TestServerSchedulesWithKey(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	kr, err := platform.NewEvidenceKeyring(1, map[uint16][]byte{1: key})
	if err != nil {
		t.Fatalf("构造测试密钥环失败: %v", err)
	}
	s := newTestServer(t, kr)
	if err := platform.CreateHospital(s.db, "h-test", "测试医院"); err != nil {
		t.Fatalf("建医院失败: %v", err)
	}
	if err := platform.CreateAsset(s.db, platform.Asset{ID: "a-mysql", HospitalID: "h-test", Kind: "db-mysql", Name: "测试 MySQL"}); err != nil {
		t.Fatalf("建资产失败: %v", err)
	}
	cookie := s.login(t, platform.DefaultAdminUser, platform.DefaultAdminPassword)
	if status, data, _ := s.do(t, http.MethodPut, "/api/v1/schedules/a-mysql",
		map[string]any{"cycle_days": 30, "password": "secret123"}, []*http.Cookie{cookie}); status != http.StatusOK {
		t.Fatalf("有密钥 PUT 应 200，实际 %d：%s", status, data)
	}
	status, data, _ := s.do(t, http.MethodGet, "/api/v1/schedules", nil, []*http.Cookie{cookie})
	if status != http.StatusOK {
		t.Fatalf("读复检列表应 200，实际 %d", status)
	}
	if !strings.Contains(string(data), "a-mysql") {
		t.Errorf("复检列表应含 a-mysql，实际 %s", data)
	}
	if strings.Contains(string(data), "secret123") {
		t.Error("复检列表不得含保存的口令原文")
	}
	// 立即执行：已开启即接受（202，异步执行结果不阻塞）。
	if status, _, _ := s.do(t, http.MethodPost, "/api/v1/schedules/a-mysql/run", nil, []*http.Cookie{cookie}); status != http.StatusAccepted {
		t.Errorf("已开启 run 应 202，实际 %d", status)
	}
	if status, _, _ := s.do(t, http.MethodDelete, "/api/v1/schedules/a-mysql", nil, []*http.Cookie{cookie}); status != http.StatusOK {
		t.Errorf("DELETE 应 200，实际 %d", status)
	}
	if status, data, _ := s.do(t, http.MethodGet, "/api/v1/schedules", nil, []*http.Cookie{cookie}); status != http.StatusOK {
		t.Fatalf("删后读列表应 200，实际 %d", status)
	} else if strings.Contains(string(data), "a-mysql") {
		t.Errorf("删后列表不应再含 a-mysql，实际 %s", data)
	}
}

func TestServerTemplateApplyPlaceholder(t *testing.T) {
	s := newTestServer(t, nil)
	cookie := s.login(t, platform.DefaultAdminUser, platform.DefaultAdminPassword)
	status, data, _ := s.do(t, http.MethodGet, "/api/v1/baseline-templates", nil, []*http.Cookie{cookie})
	if status != http.StatusOK {
		t.Fatalf("读模板列表应 200，实际 %d", status)
	}
	var listResp struct {
		Items []struct {
			ID      string `json:"id"`
			Entries []struct {
				Subject string `json:"subject"`
			} `json:"entries"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &listResp); err != nil {
		t.Fatalf("解析模板列表失败: %v", err)
	}
	ph := regexp.MustCompile(`\{[^}]+\}`)
	var tplID string
	for _, it := range listResp.Items {
		for _, e := range it.Entries {
			if ph.MatchString(e.Subject) {
				tplID = it.ID
				break
			}
		}
		if tplID != "" {
			break
		}
	}
	if tplID == "" {
		t.Fatal("内置模板中未找到带占位符的模板，无法验证占位未填 400")
	}
	status, data, _ = s.do(t, http.MethodPost, "/api/v1/baseline-templates/"+tplID+"/apply",
		map[string]any{"hospital_id": "h-test", "baseline_id": "bl-test", "values": map[string]string{}}, []*http.Cookie{cookie})
	if status != http.StatusBadRequest {
		t.Fatalf("占位未填套用应 400，实际 %d：%s", status, data)
	}
	if !strings.Contains(string(data), "请填写") {
		t.Errorf("占位未填应提示请填写，实际 %s", data)
	}
}

func TestServerTokenExpiryAndCIDR(t *testing.T) {
	s := newTestServer(t, nil)
	mint := func(cookie *http.Cookie) string {
		t.Helper()
		status, data, _ := s.do(t, http.MethodPost, "/api/v1/auth/token", map[string]any{}, []*http.Cookie{cookie})
		if status != http.StatusOK {
			t.Fatalf("铸造令牌应 200，实际 %d：%s", status, data)
		}
		var tokResp struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(data, &tokResp); err != nil || tokResp.Token == "" {
			t.Fatalf("铸造令牌响应异常: %v %s", err, data)
		}
		return tokResp.Token
	}
	cookie := s.login(t, platform.DefaultAdminUser, platform.DefaultAdminPassword)
	// 过期：把 expires_at 改到过去，令牌登录 401 且提示重新生成。
	expired := mint(cookie)
	if _, err := s.db.Exec(`UPDATE auth_tokens SET expires_at = '2000-01-01 00:00:00' WHERE name = 'super'`); err != nil {
		t.Fatal(err)
	}
	status, data, _ := s.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{"token": expired}, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("过期令牌登录应 401，实际 %d：%s", status, data)
	}
	if !strings.Contains(string(data), "已过期") {
		t.Errorf("过期令牌应提示重新生成，实际 %s", data)
	}
	// 来源限制：铸造新令牌（铸造吊销 admin 会话，故先重登口令）。
	cookie = s.login(t, platform.DefaultAdminUser, platform.DefaultAdminPassword)
	tok := mint(cookie)
	t.Setenv("MEDAUDIT_TOKEN_ALLOW_CIDR", "10.0.0.0/8")
	status, data, _ = s.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{"token": tok}, nil)
	if status != http.StatusForbidden {
		t.Fatalf("网段外令牌登录应 403，实际 %d：%s", status, data)
	}
	if !strings.Contains(string(data), "允许网段") {
		t.Errorf("网段外应提示允许网段，实际 %s", data)
	}
	t.Setenv("MEDAUDIT_TOKEN_ALLOW_CIDR", "127.0.0.0/8")
	status, _, _ = s.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{"token": tok}, nil)
	if status != http.StatusOK {
		t.Fatalf("网段内令牌登录应 200，实际 %d", status)
	}
}

func TestServerTokenCIDRCheckedFirst(t *testing.T) {
	s := newTestServer(t, nil)
	cookie := s.login(t, platform.DefaultAdminUser, platform.DefaultAdminPassword)
	status, data, _ := s.do(t, http.MethodPost, "/api/v1/auth/token", map[string]any{}, []*http.Cookie{cookie})
	if status != http.StatusOK {
		t.Fatalf("铸造令牌应 200，实际 %d：%s", status, data)
	}
	var tokResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &tokResp); err != nil || tokResp.Token == "" {
		t.Fatalf("铸造令牌响应异常: %v %s", err, data)
	}
	// 过期令牌 + 网段外：应 403（网段先行），而非 401 过期。
	if _, err := s.db.Exec(`UPDATE auth_tokens SET expires_at = '2000-01-01 00:00:00' WHERE name = 'super'`); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEDAUDIT_TOKEN_ALLOW_CIDR", "10.0.0.0/8")
	status, data, _ = s.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{"token": tokResp.Token}, nil)
	if status != http.StatusForbidden {
		t.Fatalf("网段外过期令牌应先 403，实际 %d：%s", status, data)
	}
	if !strings.Contains(string(data), "允许网段") {
		t.Errorf("网段外应提示允许网段，实际 %s", data)
	}
}

func TestServerAssetBundlesBeyondLimit(t *testing.T) {
	s := newTestServer(t, nil)
	cookie := s.login(t, platform.DefaultAdminUser, platform.DefaultAdminPassword)
	if err := platform.CreateHospital(s.db, "h-test", "测试医院"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO collection_plans (id, hospital_id, name, profile, spec, created_by)
		VALUES ('p1', 'h-test', 'P1', 'prof', '{}', 'web')`); err != nil {
		t.Fatal(err)
	}
	if err := platform.CreateAsset(s.db, platform.Asset{ID: "a-many", HospitalID: "h-test", Kind: "db-mysql", Name: "多包对象"}); err != nil {
		t.Fatal(err)
	}
	if err := platform.CreateAsset(s.db, platform.Asset{ID: "a-few", HospitalID: "h-test", Kind: "db-mysql", Name: "少包对象"}); err != nil {
		t.Fatal(err)
	}
	insert := func(id, asset string, day int) {
		t.Helper()
		ts := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC).AddDate(0, 0, day).Format("2006-01-02 15:04:05")
		if _, err := s.db.Exec(`INSERT INTO fact_bundles (id, plan_id, hospital_id, asset_id, schema_version, adapter, execution, bundle, imported_at)
			VALUES (?, 'p1', 'h-test', ?, '1', 'db-mysql', 'COMPLETE', '{"facts":[],"receipts":[]}', ?)`,
			id, asset, ts); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 120; i++ {
		insert(fmt.Sprintf("bundle-a-%03d", i), "a-many", i)
	}
	for i := 0; i < 5; i++ {
		insert(fmt.Sprintf("bundle-b-%d", i), "a-few", i)
	}
	status, data, _ := s.do(t, http.MethodGet, "/api/v1/asset-bundles?asset_id=a-many", nil, []*http.Cookie{cookie})
	if status != http.StatusOK {
		t.Fatalf("按对象取包应 200，实际 %d：%s", status, data)
	}
	var rows []platform.BundleSummary
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 120 {
		t.Fatalf("超过 100 包时应返回目标对象全部包，实际 %d", len(rows))
	}
	for _, r := range rows {
		if r.AssetID != "a-many" {
			t.Fatalf("只应返回目标对象的包，混入 %s", r.AssetID)
		}
	}
	if rows[0].ImportedAt != "2026-04-30 10:00:00" {
		t.Fatalf("首行应为最新包，实际 %s", rows[0].ImportedAt)
	}
	status, data, _ = s.do(t, http.MethodGet, "/api/v1/asset-bundles?asset_id=a-few", nil, []*http.Cookie{cookie})
	if status != http.StatusOK {
		t.Fatalf("少包对象应 200，实际 %d：%s", status, data)
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5 {
		t.Fatalf("少包对象应返回 5 包，实际 %d", len(rows))
	}
	status, _, _ = s.do(t, http.MethodGet, "/api/v1/asset-bundles", nil, []*http.Cookie{cookie})
	if status != http.StatusBadRequest {
		t.Fatalf("缺 asset_id 应 400，实际 %d", status)
	}
}
