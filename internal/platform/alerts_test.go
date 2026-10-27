package platform

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"medaudit/internal/facts"
)

func TestDriftAlertOnImport(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
	}))
	defer srv.Close()
	old := alertWebhookURL
	alertWebhookURL = func() string { return srv.URL }
	defer func() { alertWebhookURL = old }()

	db := tokenTestDB(t)
	for _, name := range []string{"demo-mysql-1", "demo-mysql-2"} {
		b, err := facts.ReadZip("../../pilot/demo-data/" + name + ".zip")
		if err != nil {
			t.Fatal(err)
		}
		if err := ImportBundle(db, b, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	alerts, err := ListAlerts(db, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Kind != "drift" || alerts[0].AddedCount == 0 || len(alerts[0].Items) == 0 {
		t.Fatalf("应有 1 条漂移告警, got %+v", alerts)
	}
	for _, it := range alerts[0].Items {
		if !alertCategories[it.Category] {
			t.Fatalf("告警样例不应含 %s", it.Category)
		}
	}
	select {
	case body := <-got:
		var m map[string]any
		if json.Unmarshal([]byte(body), &m) != nil || m["msgtype"] != "text" || !strings.Contains(body, "新增权限") {
			t.Fatalf("webhook body = %s", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("未收到 webhook 推送")
	}
	if err := AckAlert(db, alerts[0].ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if open, _ := ListAlerts(db, true); len(open) != 0 {
		t.Fatalf("确认后不应再有未处理告警: %+v", open)
	}
	if err := AckAlert(db, alerts[0].ID, "admin"); err == nil {
		t.Fatal("重复确认应报错")
	}
}
