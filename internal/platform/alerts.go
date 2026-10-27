package platform

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// 告警：新事实包与同对象上一包比对出新增授权/角色关系/主体时生成「权限漂移」告警；
// 定期复检失败时生成「复检失败」告警。配置 MEDAUDIT_ALERT_WEBHOOK 时同步推送
// （企业微信/钉钉群机器人通用的 text 消息格式）。

// alertCategories 触发漂移告警的新增类别。
var alertCategories = map[string]bool{"新增授权": true, "新增角色关系": true, "新增主体": true}

// Alert 一条告警。
type Alert struct {
	ID           int64       `json:"id"`
	HospitalID   string      `json:"hospital_id"`
	AssetID      string      `json:"asset_id"`
	Kind         string      `json:"kind"`
	BundleID     string      `json:"bundle_id"`
	PrevBundleID string      `json:"prev_bundle_id"`
	AddedCount   int         `json:"added_count"`
	Title        string      `json:"title"`
	Items        []DriftItem `json:"items,omitempty"`
	Error        string      `json:"error,omitempty"`
	CreatedAt    string      `json:"created_at"`
	AckedBy      string      `json:"acked_by"`
	AckedAt      string      `json:"acked_at"`
}

type alertDetail struct {
	Items []DriftItem `json:"items,omitempty"`
	Error string      `json:"error,omitempty"`
}

const alertSampleCap = 20

// RecordDriftAlert 将 bundleID 与同对象同适配器的上一包比对，有新增授权/角色/主体时
// 写入告警并推送。没有上一包或无新增时返回 nil, nil。
func RecordDriftAlert(db *sql.DB, bundleID string) (*Alert, error) {
	var hospitalID, assetID, adapter string
	if err := db.QueryRow(`SELECT hospital_id, asset_id, adapter FROM fact_bundles WHERE id = ?`, bundleID).
		Scan(&hospitalID, &assetID, &adapter); err != nil {
		return nil, err
	}
	var prev string
	err := db.QueryRow(`SELECT id FROM fact_bundles WHERE asset_id = ? AND adapter = ? AND id <> ?
		ORDER BY imported_at DESC, rowid DESC LIMIT 1`, assetID, adapter, bundleID).Scan(&prev)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rep, err := BundleDrift(db, prev, bundleID)
	if err != nil {
		return nil, err
	}
	// 按显示内容去重：同一授权可能经不同来源各采到一条事实。
	var items []DriftItem
	seen := map[string]bool{}
	for _, it := range rep.Added {
		key := it.Category + "\x00" + it.Subject + "\x00" + it.Detail
		if alertCategories[it.Category] && !seen[key] {
			seen[key] = true
			items = append(items, it)
		}
	}
	if len(items) == 0 {
		return nil, nil
	}
	count := len(items)
	if len(items) > alertSampleCap {
		items = items[:alertSampleCap]
	}
	a := &Alert{
		HospitalID: hospitalID, AssetID: assetID, Kind: "drift",
		BundleID: bundleID, PrevBundleID: prev, AddedCount: count,
		Title: fmt.Sprintf("%s 新增权限 %d 项", assetID, count), Items: items,
	}
	if err := insertAlert(db, a, alertDetail{Items: items}); err != nil {
		return nil, err
	}
	notifyAlert(a)
	return a, nil
}

// RecordAuditFailedAlert 定期复检失败告警。
func RecordAuditFailedAlert(db *sql.DB, hospitalID, assetID, errMsg string) (*Alert, error) {
	a := &Alert{
		HospitalID: hospitalID, AssetID: assetID, Kind: "audit_failed",
		Title: assetID + " 定期复检失败", Error: errMsg,
	}
	if err := insertAlert(db, a, alertDetail{Error: errMsg}); err != nil {
		return nil, err
	}
	notifyAlert(a)
	return a, nil
}

func insertAlert(db *sql.DB, a *Alert, d alertDetail) error {
	raw, _ := json.Marshal(d)
	a.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	res, err := db.Exec(`INSERT INTO alerts (hospital_id, asset_id, kind, bundle_id, prev_bundle_id, added_count, title, detail, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.HospitalID, a.AssetID, a.Kind, a.BundleID, a.PrevBundleID, a.AddedCount, a.Title, string(raw), a.CreatedAt)
	if err != nil {
		return err
	}
	a.ID, _ = res.LastInsertId()
	return nil
}

// ListAlerts 列出告警（openOnly 只看未确认），新的在前，至多 200 条。
func ListAlerts(db *sql.DB, openOnly bool) ([]Alert, error) {
	q := `SELECT id, hospital_id, asset_id, kind, bundle_id, prev_bundle_id, added_count, title, detail, created_at, acked_by, acked_at FROM alerts`
	if openOnly {
		q += ` WHERE acked_at = ''`
	}
	rows, err := db.Query(q + ` ORDER BY id DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		var detail string
		if err := rows.Scan(&a.ID, &a.HospitalID, &a.AssetID, &a.Kind, &a.BundleID, &a.PrevBundleID,
			&a.AddedCount, &a.Title, &detail, &a.CreatedAt, &a.AckedBy, &a.AckedAt); err != nil {
			return nil, err
		}
		var d alertDetail
		_ = json.Unmarshal([]byte(detail), &d)
		a.Items, a.Error = d.Items, d.Error
		out = append(out, a)
	}
	return out, rows.Err()
}

// AckAlert 确认（已知悉）一条告警。
func AckAlert(db *sql.DB, id int64, by string) error {
	res, err := db.Exec(`UPDATE alerts SET acked_by = ?, acked_at = ? WHERE id = ? AND acked_at = ''`,
		by, time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("告警 %d 不存在或已确认", id)
	}
	return nil
}

// alertText 推送文本。
func alertText(a *Alert) string {
	var b strings.Builder
	b.WriteString("【MedAudit 告警】" + a.Title + "\n")
	b.WriteString("医院：" + a.HospitalID + "  对象：" + a.AssetID + "\n")
	for i, it := range a.Items {
		if i == 5 {
			fmt.Fprintf(&b, "……共 %d 项，请登录平台查看\n", a.AddedCount)
			break
		}
		b.WriteString("· " + it.Category + "：" + it.Subject)
		if it.Detail != "" {
			b.WriteString("（" + it.Detail + "）")
		}
		b.WriteString("\n")
	}
	if a.Error != "" {
		b.WriteString("原因：" + a.Error + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// alertWebhookURL 测试可替换。
var alertWebhookURL = func() string { return os.Getenv("MEDAUDIT_ALERT_WEBHOOK") }

// notifyAlert 异步推送到 Webhook（失败只记日志，不影响告警落库）。
func notifyAlert(a *Alert) {
	url := strings.TrimSpace(alertWebhookURL())
	if url == "" {
		return
	}
	body, _ := json.Marshal(map[string]any{
		"msgtype": "text",
		"text":    map[string]string{"content": alertText(a)},
	})
	go func() {
		c := &http.Client{Timeout: 10 * time.Second}
		resp, err := c.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("[alert] Webhook 推送失败: %v", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			log.Printf("[alert] Webhook 返回 HTTP %d", resp.StatusCode)
		}
	}()
}
