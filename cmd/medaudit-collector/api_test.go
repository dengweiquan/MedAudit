package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 静态复核回归：上传认证——令牌登录换会话，令牌不落盘；登录被拒时上传不得继续。
func TestLoginWithToken(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/login" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		if gotBody["token"] != "tok-123" {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "medaudit_session", Value: "sess-abc", Path: "/"})
		w.Write([]byte(`{"username":"admin"}`))
	}))
	defer srv.Close()

	cookie, err := loginWithToken(context.Background(), srv.URL, "tok-123")
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "medaudit_session=sess-abc" {
		t.Fatalf("want session cookie, got %q", cookie)
	}
	if gotBody["token"] != "tok-123" {
		t.Fatalf("login body must carry the token, got %v", gotBody)
	}

	if _, err := loginWithToken(context.Background(), srv.URL, "wrong"); err == nil {
		t.Fatal("wrong token must be rejected")
	} else if !strings.Contains(err.Error(), "401") {
		t.Fatalf("rejection must mention 401, got %v", err)
	}
}
