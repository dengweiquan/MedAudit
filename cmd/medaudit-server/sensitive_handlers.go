package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"medaudit/internal/facts"
	"medaudit/internal/platform"
)

// M5-5 敏感对象标记接口。权限模型与平台其余变更接口一致：登录会话
// （authMiddleware 拦截未登录）+ 医院/资产归属校验；写操作由
// opLogMiddleware 落哈希链操作日志，本文件补注记（标记对象身份）。
// 只存对象标识与敏感类别，不存真实患者数据。

func registerSensitiveRoutes(mux *http.ServeMux, db *sql.DB) {
	// GET /api/v1/sensitive-labels?hospital_id=&asset_id=
	// POST /api/v1/sensitive-labels {hospital_id, asset_id, database?, schema, table, column?, category}
	mux.HandleFunc("/api/v1/sensitive-labels", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			hospitalID := r.URL.Query().Get("hospital_id")
			assetID := r.URL.Query().Get("asset_id")
			if hospitalID == "" {
				http.Error(w, "hospital_id 必填", http.StatusBadRequest)
				return
			}
			if _, err := checkSensitiveScope(db, hospitalID, assetID); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			labels, err := platform.ListSensitiveLabels(db, hospitalID, assetID)
			if err != nil {
				http.Error(w, "读取标记失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if labels == nil {
				labels = []platform.SensitiveLabel{}
			}
			writeJSON(w, labels)
		case http.MethodPost:
			var req struct {
				HospitalID string `json:"hospital_id"`
				AssetID    string `json:"asset_id"`
				Database   string `json:"database"`
				Schema     string `json:"schema"`
				Table      string `json:"table"`
				Column     string `json:"column"`
				Category   string `json:"category"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "请求格式非法", http.StatusBadRequest)
				return
			}
			kind, err := checkSensitiveScope(db, req.HospitalID, req.AssetID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			switch kind {
			case "db-oracle", "db-mysql", "db-postgres", "db-sqlserver":
			default:
				http.Error(w, "该资产类型不支持敏感对象标记（仅数据库资产）", http.StatusBadRequest)
				return
			}
			// 操作人由 opLogMiddleware 从会话取，此处不重复记。
			label, err := platform.UpsertSensitiveLabel(db, facts.TargetType(kind), "", platform.SensitiveLabel{
				Hospital: req.HospitalID, Asset: req.AssetID, Database: req.Database,
				Schema: req.Schema, Table: req.Table, Column: req.Column, Category: req.Category,
			})
			if err != nil {
				http.Error(w, "保存标记失败: "+err.Error(), http.StatusBadRequest)
				return
			}
			opNote(r, "", "敏感标记："+labelDisplay(label))
			writeJSON(w, label)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// PUT /api/v1/sensitive-labels/{id} {category}
	// DELETE /api/v1/sensitive-labels/{id}
	mux.HandleFunc("/api/v1/sensitive-labels/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/sensitive-labels/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var req struct {
				Category string `json:"category"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "请求格式非法", http.StatusBadRequest)
				return
			}
			label, err := platform.UpdateSensitiveLabelCategory(db, id, req.Category)
			if err == sql.ErrNoRows {
				http.Error(w, "标记不存在", http.StatusNotFound)
				return
			}
			if err != nil {
				http.Error(w, "更新标记失败: "+err.Error(), http.StatusBadRequest)
				return
			}
			opNote(r, "", "敏感标记改类别："+labelDisplay(label))
			writeJSON(w, label)
		case http.MethodDelete:
			var label platform.SensitiveLabel
			_ = db.QueryRow(`SELECT hospital_id, asset_id, database_name, schema_name, table_name,
				column_name, category FROM sensitive_labels WHERE id = ?`, id).
				Scan(&label.Hospital, &label.Asset, &label.Database, &label.Schema,
					&label.Table, &label.Column, &label.Category)
			ok, err := platform.DeleteSensitiveLabel(db, id)
			if err != nil {
				http.Error(w, "删除标记失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if !ok {
				http.Error(w, "标记不存在", http.StatusNotFound)
				return
			}
			opNote(r, "", "敏感标记删除："+labelDisplay(label))
			writeJSON(w, map[string]string{"status": "ok", "id": id})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

// checkSensitiveScope 校验医院存在、资产存在且归属该医院，返回资产 kind。
// assetID 为空时只校验医院（列表接口用）。
func checkSensitiveScope(db *sql.DB, hospitalID, assetID string) (string, error) {
	var dummy string
	if err := db.QueryRow(`SELECT id FROM hospitals WHERE id = ?`, hospitalID).Scan(&dummy); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("医院不存在: %s", hospitalID)
		}
		return "", err
	}
	if assetID == "" {
		return "", nil
	}
	var kind, hosp string
	if err := db.QueryRow(`SELECT kind, hospital_id FROM assets WHERE id = ?`, assetID).Scan(&kind, &hosp); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("资产不存在: %s", assetID)
		}
		return "", err
	}
	if hosp != hospitalID {
		return "", fmt.Errorf("资产不归属该医院")
	}
	return kind, nil
}

// labelDisplay 标记展示串（用于操作日志注记，不含真实数据）。
func labelDisplay(l platform.SensitiveLabel) string {
	s := l.Schema + "." + l.Table
	if l.Database != "" {
		s = l.Database + "." + s
	}
	if l.Column != "" {
		s += "(" + l.Column + ")"
	}
	return s + " [" + l.Category + "]"
}
