package platform

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"medaudit/internal/rules"
)

// ConnConfig 数据库连接参数（非机密部分），登记在 assets.labels 的 JSON 中。
// 口令永不落库：审计时由用户在页面输入，仅经子进程环境变量传递给采集器。
type ConnConfig struct {
	Engine  string `json:"engine"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	DBName  string `json:"dbname,omitempty"`
	Service string `json:"service,omitempty"`
	SSLMode string `json:"sslmode,omitempty"`
}

var engineByKind = map[string]string{
	"db-mysql": "mysql", "db-sqlserver": "sqlserver",
	"db-oracle": "oracle", "db-postgres": "postgres",
}

// AuditRunResult 一键审计结果。
type AuditRunResult struct {
	BundleID   string             `json:"bundle_id"`
	Facts      int                `json:"facts"`
	Receipts   int                `json:"receipts"`
	Evaluation *EvaluationSummary `json:"evaluation"`
	ReportID   string             `json:"report_id"`
}

var auditMu sync.Mutex // 一键审计串行执行（子进程环境与目标库压力都更可控）

// RunDBAudit 对已登记的数据库资产执行一键审计：
// 调采集器真采集 → 导入 → 评估 → 生成报告。口令仅存在于本次子进程环境，不落库、不落配置。
func RunDBAudit(ctx context.Context, db *sql.DB, reg *rules.Registry, kr *EvidenceKeyring,
	collectorBin, assetID, password, baselineID, createdBy string) (*AuditRunResult, error) {

	var hospitalID, kind string
	var labels sql.NullString
	err := db.QueryRow(`SELECT hospital_id, kind, labels FROM assets WHERE id = ?`, assetID).
		Scan(&hospitalID, &kind, &labels)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("资产 %s 不存在", assetID)
	}
	if err != nil {
		return nil, err
	}
	engine, ok := engineByKind[kind]
	if !ok {
		return nil, fmt.Errorf("资产类型 %s 不支持一键审计（仅数据库类）", kind)
	}
	if !labels.Valid || strings.TrimSpace(labels.String) == "" {
		return nil, fmt.Errorf("资产 %s 未登记连接参数，请先编辑资产补全连接信息", assetID)
	}
	var cc ConnConfig
	if err := json.Unmarshal([]byte(labels.String), &cc); err != nil {
		return nil, fmt.Errorf("连接参数解析失败: %w", err)
	}
	if cc.Engine != "" {
		engine = cc.Engine
	}
	if cc.Host == "" || cc.Port == 0 || cc.User == "" {
		return nil, fmt.Errorf("连接参数不完整（host/port/user 必填）")
	}
	if password == "" {
		return nil, fmt.Errorf("口令必填（仅本次审计使用，不保存）")
	}
	if collectorBin == "" {
		return nil, fmt.Errorf("服务端未配置采集器（MEDAUDIT_COLLECTOR_BIN），一键审计不可用")
	}

	auditMu.Lock()
	defer auditMu.Unlock()

	dir, err := os.MkdirTemp("", "medaudit-run-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	planID := "plan-web-" + assetID
	var sb strings.Builder
	fmt.Fprintf(&sb, "engine: %s\nhost: %q\nport: %d\nuser: %q\npassword_env: MEDAUDIT_RUN_PW\n",
		engine, cc.Host, cc.Port, cc.User)
	if engine == "oracle" {
		fmt.Fprintf(&sb, "service: %q\n", cc.Service)
	} else if cc.DBName != "" {
		fmt.Fprintf(&sb, "dbname: %q\n", cc.DBName)
	}
	if cc.SSLMode != "" {
		fmt.Fprintf(&sb, "sslmode: %q\n", cc.SSLMode)
	}
	fmt.Fprintf(&sb, "hospital_id: %q\nasset_id: %q\nplan_id: %q\n", hospitalID, assetID, planID)
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(sb.String()), 0o600); err != nil {
		return nil, err
	}
	zipPath := filepath.Join(dir, "bundle.zip")

	runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(runCtx, collectorBin, "db",
		"-engine", engine, "-config", cfgPath, "-out", zipPath)
	env := append(os.Environ(), "MEDAUDIT_RUN_PW="+password)
	if engine == "oracle" {
		lib := os.Getenv("MEDAUDIT_ORACLE_LIB")
		if lib == "" {
			lib = "/opt/oracle/instantclient_19_23"
		}
		env = append(env, "LD_LIBRARY_PATH="+lib)
	}
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		tail := tailRunes(strings.TrimSpace(stderr.String()), 500)
		return nil, fmt.Errorf("采集失败: %v（%s）%s", err, tail, oraHint(tail))
	}
	rawZip, err := os.ReadFile(zipPath)
	if err != nil {
		return nil, err
	}
	res, err := importEvaluateReport(db, reg, kr, rawZip, hospitalID, planID, baselineID, createdBy)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// tailRunes 取字符串尾部至多 n 个字符（按 rune 切分，避免按字节截断
// 切碎 UTF-8 汉字出现乱码 \uFFFD）。
func tailRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[len(r)-n:]
	}
	return string(r)
}

// oraHint 把常见 Oracle 连接错误翻译成给客户看的提示。
func oraHint(s string) string {
	switch {
	case strings.Contains(s, "ORA-01017"):
		return "；提示：用户名或口令不正确，请核对后重试"
	case strings.Contains(s, "ORA-12170"), strings.Contains(s, "ORA-12541"), strings.Contains(s, "ORA-12514"):
		return "；提示：无法连接目标数据库（网络不通、监听未启动或服务名不正确）"
	}
	return ""
}
