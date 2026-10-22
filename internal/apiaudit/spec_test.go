package apiaudit

import "testing"

func TestParseOpenAPIBasic(t *testing.T) {
	ops, err := ParseOpenAPI([]byte(`{"openapi":"3.0.3","paths":{
		"/api/users/{user_id}":{"get":{},"parameters":[]},
		"/api/notes":{"post":{}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 2 {
		t.Fatalf("期望 2 个操作, got %d", len(ops))
	}
	found := false
	for _, op := range ops {
		if op.Path == "/api/users/{user_id}" && op.Method == "GET" {
			found = true
		}
	}
	if !found {
		t.Fatal("未解析出 GET /api/users/{user_id}")
	}
}

func TestParseHARTemplatize(t *testing.T) {
	ops, err := ParseHAR([]byte(`{"log":{"entries":[
		{"request":{"method":"GET","url":"http://x.test/api/users/42"}},
		{"request":{"method":"GET","url":"http://x.test/api/users/43"}},
		{"request":{"method":"GET","url":"http://x.test/api/users/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"}}
	]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 || ops[0].Path != "/api/users/{id}" {
		t.Fatalf("HAR 模板化去重错误: %+v", ops)
	}
}

func TestInstantiate(t *testing.T) {
	p, ok := instantiate("/api/users/{user_id}/posts/{post_id}",
		map[string]string{"user_id": "2", "post_id": "9"})
	if !ok || p != "/api/users/2/posts/9" {
		t.Fatalf("填充失败: %q %v", p, ok)
	}
	if _, ok := instantiate("/api/users/{user_id}", map[string]string{}); ok {
		t.Fatal("缺参数应返回 ok=false")
	}
}
