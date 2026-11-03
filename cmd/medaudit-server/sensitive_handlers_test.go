package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"medaudit/internal/platform"
)

// M5-5 敏感标记接口：归属校验、幂等、改删、未登录拦截、操作日志注记。
func TestServerSensitiveLabels(t *testing.T) {
	s := newTestServer(t, nil)
	cookie := s.login(t, platform.DefaultAdminUser, platform.DefaultAdminPassword)
	authed := []*http.Cookie{cookie}
	if err := platform.CreateHospital(s.db, "h1", "医院一"); err != nil {
		t.Fatal(err)
	}
	if err := platform.CreateHospital(s.db, "h2", "医院二"); err != nil {
		t.Fatal(err)
	}
	if err := platform.CreateAsset(s.db, platform.Asset{ID: "a1", HospitalID: "h1", Kind: "db-oracle", Name: "Ora"}); err != nil {
		t.Fatal(err)
	}
	if err := platform.CreateAsset(s.db, platform.Asset{ID: "a9", HospitalID: "h1", Kind: "os-linux", Name: "Linux"}); err != nil {
		t.Fatal(err)
	}

	// 未登录拦截。
	status, _, _ := s.do(t, http.MethodPost, "/api/v1/sensitive-labels",
		map[string]any{"hospital_id": "h1", "asset_id": "a1", "schema": "HIS", "table": "PATIENTS", "category": "患者身份"}, nil)
	if status != http.StatusUnauthorized {
		t.Errorf("未登录创建应 401，实际 %d", status)
	}
	// 归属错误：资产不归属该医院。
	status, _, _ = s.do(t, http.MethodPost, "/api/v1/sensitive-labels",
		map[string]any{"hospital_id": "h2", "asset_id": "a1", "schema": "HIS", "table": "PATIENTS", "category": "患者身份"}, authed)
	if status != http.StatusBadRequest {
		t.Errorf("跨医院资产应 400，实际 %d", status)
	}
	// 非数据库资产拒绝。
	status, _, _ = s.do(t, http.MethodPost, "/api/v1/sensitive-labels",
		map[string]any{"hospital_id": "h1", "asset_id": "a9", "schema": "root", "table": "passwd", "category": "患者身份"}, authed)
	if status != http.StatusBadRequest {
		t.Errorf("非数据库资产应 400，实际 %d", status)
	}
	// 创建（小写输入应规范化大写）。
	status, data, _ := s.do(t, http.MethodPost, "/api/v1/sensitive-labels",
		map[string]any{"hospital_id": "h1", "asset_id": "a1", "schema": "his", "table": "patients", "category": "患者身份"}, authed)
	if status != http.StatusOK {
		t.Fatalf("创建应 200，实际 %d：%s", status, data)
	}
	var created platform.SensitiveLabel
	if err := json.Unmarshal(data, &created); err != nil {
		t.Fatal(err)
	}
	if created.Schema != "HIS" || created.Table != "PATIENTS" || created.Version != 1 {
		t.Errorf("创建应规范化大写且 version=1，得到 %+v", created)
	}
	// 重复请求幂等：同 ID、version 不变。
	status, data, _ = s.do(t, http.MethodPost, "/api/v1/sensitive-labels",
		map[string]any{"hospital_id": "h1", "asset_id": "a1", "schema": "HIS", "table": "PATIENTS", "category": "患者身份"}, authed)
	if status != http.StatusOK {
		t.Fatalf("重复创建应 200，实际 %d：%s", status, data)
	}
	var dup platform.SensitiveLabel
	if err := json.Unmarshal(data, &dup); err != nil {
		t.Fatal(err)
	}
	if dup.ID != created.ID || dup.Version != 1 {
		t.Errorf("重复请求应幂等，得到 %+v", dup)
	}
	// 列表 1 行。
	status, data, _ = s.do(t, http.MethodGet, "/api/v1/sensitive-labels?hospital_id=h1&asset_id=a1", nil, authed)
	if status != http.StatusOK {
		t.Fatalf("列表应 200，实际 %d：%s", status, data)
	}
	var rows []platform.SensitiveLabel
	if err := json.Unmarshal(data, &rows); err != nil || len(rows) != 1 {
		t.Fatalf("列表应 1 行，得到 %d（err=%v）", len(rows), err)
	}
	// 改类别 version +1。
	status, data, _ = s.do(t, http.MethodPut, "/api/v1/sensitive-labels/"+created.ID,
		map[string]any{"category": "诊疗"}, authed)
	if status != http.StatusOK {
		t.Fatalf("改类别应 200，实际 %d：%s", status, data)
	}
	var upd platform.SensitiveLabel
	if err := json.Unmarshal(data, &upd); err != nil || upd.Version != 2 {
		t.Fatalf("改类别应 version 2，得到 %+v（err=%v）", upd, err)
	}
	// 删后列表为空；操作日志含标记注记。
	status, _, _ = s.do(t, http.MethodDelete, "/api/v1/sensitive-labels/"+created.ID, nil, authed)
	if status != http.StatusOK {
		t.Fatalf("删除应 200，实际 %d", status)
	}
	status, data, _ = s.do(t, http.MethodGet, "/api/v1/sensitive-labels?hospital_id=h1&asset_id=a1", nil, authed)
	if err := json.Unmarshal(data, &rows); err != nil || len(rows) != 0 {
		t.Fatalf("删除后列表应为空，得到 %d（err=%v）", len(rows), err)
	}
	found := false
	for _, e := range opEntries(t, s.db) {
		if strings.Contains(e.Note, "敏感标记") && strings.Contains(e.Note, "HIS.PATIENTS") {
			found = true
		}
	}
	if !found {
		t.Errorf("操作日志应含标记变更注记")
	}
}
