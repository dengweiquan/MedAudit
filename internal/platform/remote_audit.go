package platform

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"medaudit/internal/collect/oshpux"
	"medaudit/internal/facts"
	"medaudit/internal/remote"
	"medaudit/internal/rules"
)

// RemoteConfig 远程推送连接参数（非机密部分），登记在 assets.labels 的 JSON 中。
// 口令永不落库：审计时由用户在页面输入，仅在本次传输会话中使用。
type RemoteConfig struct {
	Transport string `json:"transport,omitempty"` // ssh|winrm（可空，按资产类型推断）
	Host      string `json:"host"`
	Port      int    `json:"port,omitempty"` // ssh 默认 22，winrm 默认 5985
	User      string `json:"user"`
	ServerURL string `json:"server_url,omitempty"` // WinRM 专用：目标机拉取采集器 exe 的服务地址
	HostKeyFP string `json:"host_key,omitempty"`   // SSH 可选：登记的主机密钥 SHA256 指纹
	MWType    string `json:"mw_type,omitempty"`    // 中间件类型覆盖（tomcat|nginx|weblogic|iis）
	MWHome    string `json:"mw_home,omitempty"`    // 中间件 home（IIS 可空 = 系统默认路径）
	Services  string `json:"services,omitempty"`   // Linux OS 可选：systemd 单元白名单，逗号分隔
}

var remoteKinds = map[string]struct{ transport, sub string }{
	"os-linux":    {"ssh", "os"},
	"os-windows":  {"winrm", "os"},
	"os-hpux":     {"ssh", "os"}, // M21：SSH 命令采集（无二进制推送）
	"mw-tomcat":   {"ssh", "mw"},
	"mw-nginx":    {"ssh", "mw"},
	"mw-weblogic": {"ssh", "mw"},
	"mw-iis":      {"winrm", "mw"},
}

var mwTypeByKind = map[string]string{
	"mw-tomcat": "tomcat", "mw-nginx": "nginx", "mw-weblogic": "weblogic", "mw-iis": "iis",
}

// ---------- 一次性下载令牌（WinRM 拉取采集器 exe 用） ----------

type tokenEntry struct {
	path string
	exp  time.Time
}

// TokenStore 进程内存中的单次有效下载令牌：Redeem 成功即失效。
type TokenStore struct {
	mu sync.Mutex
	m  map[string]tokenEntry
}

func NewTokenStore() *TokenStore { return &TokenStore{m: make(map[string]tokenEntry)} }

func (t *TokenStore) Mint(filePath string, ttl time.Duration) string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	tok := hex.EncodeToString(b[:])
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for k, e := range t.m { // 顺手清过期
		if now.After(e.exp) {
			delete(t.m, k)
		}
	}
	t.m[tok] = tokenEntry{path: filePath, exp: now.Add(ttl)}
	return tok
}

func (t *TokenStore) Redeem(tok string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.m[tok]
	if !ok || time.Now().After(e.exp) {
		delete(t.m, tok)
		return "", false
	}
	delete(t.m, tok) // 单次有效
	return e.path, true
}

// ---------- 远程推送审计 ----------

// RemoteAuditResult 在一键审计结果上附加传输信息。
type RemoteAuditResult struct {
	*AuditRunResult
	Transport          string `json:"transport"`
	HostKeyFingerprint string `json:"host_key_fingerprint,omitempty"`
}

func randSuffix() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// shq 单引号包裹一个 shell 参数（资产登记值含空格/引号时也安全）。
func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func stderrTail(b []byte) string {
	return tailRunes(strings.TrimSpace(string(b)), 500)
}

// importEvaluateReport 事实包收尾管线（DB 一键审计与远程推送共用）：
// 解 zip → 校验 → 导入 → 评估 → 生成报告。
func importEvaluateReport(db *sql.DB, reg *rules.Registry, kr *EvidenceKeyring,
	rawZip []byte, hospitalID, planID, baselineID, createdBy string) (*AuditRunResult, error) {
	zr, err := zip.NewReader(bytes.NewReader(rawZip), int64(len(rawZip)))
	if err != nil {
		return nil, fmt.Errorf("采集产物解析失败: %w", err)
	}
	var bundleJSON []byte
	for _, f := range zr.File {
		if f.Name == "bundle.json" || strings.HasSuffix(f.Name, "/bundle.json") {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			var buf bytes.Buffer
			if _, err := buf.ReadFrom(rc); err != nil {
				rc.Close()
				return nil, err
			}
			rc.Close()
			bundleJSON = buf.Bytes()
			break
		}
	}
	if bundleJSON == nil {
		return nil, fmt.Errorf("采集产物缺少 bundle.json")
	}
	var bundle facts.FactBundle
	if err := json.Unmarshal(bundleJSON, &bundle); err != nil {
		return nil, fmt.Errorf("事实包解析失败: %w", err)
	}
	if problems := bundle.Validate(); len(problems) > 0 {
		return nil, fmt.Errorf("事实包校验失败: %s", strings.Join(problems, "; "))
	}
	if err := ImportBundle(db, &bundle, rawZip, kr); err != nil {
		return nil, fmt.Errorf("导入失败: %w", err)
	}
	summary, err := EvaluateBundle(db, reg, bundle.BundleID, baselineID)
	if err != nil {
		return nil, fmt.Errorf("评估失败: %w", err)
	}
	reportID, err := GenerateReport(db, hospitalID, planID, bundle.BundleID, createdBy)
	if err != nil {
		return nil, fmt.Errorf("报告生成失败: %w", err)
	}
	return &AuditRunResult{
		BundleID:   bundle.BundleID,
		Facts:      len(bundle.Facts),
		Receipts:   len(bundle.Receipts),
		Evaluation: summary,
		ReportID:   reportID,
	}, nil
}

// RunRemoteAudit 对已登记远程参数的 OS/中间件资产执行远程推送审计：
// 推送采集器 → 目标机执行 → 取回事实包 → 导入/评估/报告。
// 口令仅存在于本次传输会话，不落库、不落盘、不进日志。
func RunRemoteAudit(ctx context.Context, db *sql.DB, reg *rules.Registry, kr *EvidenceKeyring,
	linuxBin, winBin string, tokens *TokenStore,
	assetID, password, baselineID, createdBy string) (*RemoteAuditResult, error) {
	if err := licenseGate(); err != nil {
		return nil, err
	}

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
	spec, ok := remoteKinds[kind]
	if !ok {
		return nil, fmt.Errorf("资产类型 %s 不支持远程推送审计（仅 OS 与中间件类）", kind)
	}
	if !labels.Valid || strings.TrimSpace(labels.String) == "" {
		return nil, fmt.Errorf("资产 %s 未登记远程连接参数，请先编辑资产补全", assetID)
	}
	var rc RemoteConfig
	if err := json.Unmarshal([]byte(labels.String), &rc); err != nil {
		return nil, fmt.Errorf("远程连接参数解析失败: %w", err)
	}
	transport := rc.Transport
	if transport == "" {
		transport = spec.transport
	}
	if transport != spec.transport {
		return nil, fmt.Errorf("资产类型 %s 需用 %s 传输，登记的是 %s", kind, spec.transport, transport)
	}
	if rc.Host == "" || rc.User == "" {
		return nil, fmt.Errorf("远程连接参数不完整（host/user 必填）")
	}
	if password == "" {
		return nil, fmt.Errorf("口令必填（仅本次审计使用，不保存）")
	}
	mwType := rc.MWType
	if spec.sub == "mw" {
		if mwType == "" {
			mwType = mwTypeByKind[kind]
		}
		if mwType != "iis" && rc.MWHome == "" {
			return nil, fmt.Errorf("中间件资产未登记 mw_home（采集目录）")
		}
	}

	auditMu.Lock()
	defer auditMu.Unlock()

	runCtx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	planID := "plan-web-" + assetID
	suffix := randSuffix()

	// M21：HP-UX 无可推送的 Go 二进制（Go 无该目标平台），改走 SSH
	// 远程命令采集：服务端发固定只读命令集，本地解析成包后走同一
	// 导入-评估-报告管线。
	if kind == "os-hpux" {
		port := rc.Port
		if port == 0 {
			port = 22
		}
		cli, err := remote.DialSSH(runCtx, rc.Host, port, rc.User, password, rc.HostKeyFP)
		if err != nil {
			return nil, fmt.Errorf("SSH 连接失败: %w", err)
		}
		defer cli.Close()
		b, err := oshpux.Collect(hpuxCmdRunner{ctx: runCtx, cli: cli}, oshpux.Config{
			HospitalID: hospitalID, AssetID: assetID, PlanID: planID,
			CollectorIdentity: "ssh:" + rc.User + "@" + rc.Host,
			CollectorVersion:  "ssh-remote",
		})
		if err != nil {
			return nil, fmt.Errorf("HP-UX 采集失败: %w", err)
		}
		zb, err := oshpux.ZipBytes(b)
		if err != nil {
			return nil, err
		}
		res, err := importEvaluateReport(db, reg, kr, zb, hospitalID, planID, baselineID, createdBy)
		if err != nil {
			return nil, err
		}
		return &RemoteAuditResult{AuditRunResult: res, Transport: "ssh", HostKeyFingerprint: cli.Fingerprint}, nil
	}

	var zipBytes []byte
	var fingerprint string

	if transport == "ssh" {
		if linuxBin == "" {
			return nil, fmt.Errorf("服务端未配置 Linux 采集器（MEDAUDIT_COLLECTOR_BIN），远程审计不可用")
		}
		binData, err := os.ReadFile(linuxBin)
		if err != nil {
			return nil, fmt.Errorf("读取服务端采集器失败: %w", err)
		}
		port := rc.Port
		if port == 0 {
			port = 22
		}
		cli, err := remote.DialSSH(runCtx, rc.Host, port, rc.User, password, rc.HostKeyFP)
		if err != nil {
			return nil, err
		}
		defer cli.Close()
		fingerprint = cli.Fingerprint
		dir := "/tmp/medaudit-push-" + suffix
		if _, se, err := cli.Run(runCtx, "mkdir -p "+dir); err != nil {
			return nil, fmt.Errorf("远程建目录失败: %v（%s）", err, stderrTail(se))
		}
		defer cli.Run(context.Background(), "rm -rf "+dir) //nolint:errcheck
		binPath := dir + "/collector"
		if err := cli.PutReader(runCtx, bytes.NewReader(binData), binPath, "700"); err != nil {
			return nil, err
		}
		args := collectorArgs(spec.sub, mwType, rc, dir+"/bundle.zip", hospitalID, assetID, planID)
		var cmd strings.Builder
		cmd.WriteString(binPath)
		for _, a := range args {
			cmd.WriteString(" " + shq(a))
		}
		_, se, err := cli.Run(runCtx, cmd.String())
		if err != nil {
			return nil, fmt.Errorf("远程采集失败: %v（%s）", err, stderrTail(se))
		}
		zipBytes, err = cli.GetFile(runCtx, dir+"/bundle.zip", 64<<20)
		if err != nil {
			return nil, err
		}
	} else { // winrm
		if winBin == "" {
			return nil, fmt.Errorf("服务端未配置 Windows 采集器（MEDAUDIT_COLLECTOR_WIN_BIN），远程审计不可用")
		}
		if rc.ServerURL == "" {
			return nil, fmt.Errorf("Windows 推送需在资产登记 server_url（目标机可达的服务地址，用于拉取采集器）")
		}
		port := rc.Port
		if port == 0 {
			port = 5985
		}
		cli, err := remote.DialWinRM(rc.Host, port, rc.User, password)
		if err != nil {
			return nil, err
		}
		dir, err := cli.MkDirTemp(runCtx, suffix)
		if err != nil {
			return nil, err
		}
		defer cli.RemoveDir(context.Background(), dir)
		token := tokens.Mint(winBin, 5*time.Minute)
		url := strings.TrimRight(rc.ServerURL, "/") + "/api/v1/agent/download?token=" + token
		exePath := dir + `\collector.exe`
		size, err := cli.Download(runCtx, url, exePath)
		if err != nil {
			return nil, err
		}
		if size < 1<<20 {
			return nil, fmt.Errorf("远程采集器下载不完整（%d 字节）", size)
		}
		args := collectorArgs(spec.sub, mwType, rc, dir+`\bundle.zip`, hospitalID, assetID, planID)
		_, se, code, err := cli.RunCollector(runCtx, exePath, args...)
		if err != nil {
			return nil, fmt.Errorf("远程采集失败: %w", err)
		}
		if code != 0 {
			return nil, fmt.Errorf("远程采集失败（退出码 %d）: %s", code, stderrTail([]byte(se)))
		}
		zipBytes, err = cli.FetchFileBase64(runCtx, dir+`\bundle.zip`, 64<<20)
		if err != nil {
			return nil, err
		}
	}

	res, err := importEvaluateReport(db, reg, kr, zipBytes, hospitalID, planID, baselineID, createdBy)
	if err != nil {
		return nil, err
	}
	return &RemoteAuditResult{AuditRunResult: res, Transport: transport, HostKeyFingerprint: fingerprint}, nil
}

// collectorArgs 组装采集器参数（不含二进制路径本身）。
// 参数均为服务端生成或资产登记值；SSH 侧逐个 shell 引号包裹，WinRM 侧由 RunCollector 包裹。
func collectorArgs(sub, mwType string, rc RemoteConfig, outPath, hospitalID, assetID, planID string) []string {
	if sub == "os" {
		args := []string{"os", "--out", outPath, "--hospital", hospitalID, "--asset", assetID, "--plan", planID}
		if rc.Services != "" {
			args = append(args, "--services", rc.Services)
		}
		return args
	}
	args := []string{"mw", "--type", mwType}
	if rc.MWHome != "" {
		args = append(args, "--home", rc.MWHome)
	}
	return append(args, "--out", outPath, "--hospital", hospitalID, "--asset", assetID, "--plan", planID)
}

// hpuxCmdRunner 把 oshpux 命令键映射到固定命令并在 SSH 会话中执行。
type hpuxCmdRunner struct {
	ctx context.Context
	cli *remote.SSHClient
}

func (r hpuxCmdRunner) Run(key string) (string, error) {
	cmd, ok := oshpux.Commands[key]
	if !ok {
		return "", fmt.Errorf("未知命令键 %s", key)
	}
	out, _, err := r.cli.Run(r.ctx, cmd)
	return string(out), err
}
