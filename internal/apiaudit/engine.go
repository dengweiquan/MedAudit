package apiaudit

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Conclusion 单个探针的结论（与平台结论口径一致，外加 NOT_RUN）。
type Conclusion string

const (
	ConclPass    Conclusion = "PASS"
	ConclFail    Conclusion = "FAIL"
	ConclUnknown Conclusion = "UNKNOWN"
	ConclNotRun  Conclusion = "NOT_RUN"
)

// Check 一次差分探针的结果。
type Check struct {
	Endpoint    string     `json:"endpoint"` // "GET /api/users/{user_id}"
	Identity    string     `json:"identity"`
	Probe       string     `json:"probe"` // direct | self | cross-owner:<name>
	Expectation AccessKind `json:"expectation"`
	Status      int        `json:"status,omitempty"` // HTTP 状态码；0 = 传输错误
	Conclusion  Conclusion `json:"conclusion"`
	Detail      string     `json:"detail"`
}

// Report 一次越权检测的完整报告。
type Report struct {
	ReportID   string         `json:"report_id"`
	Target     string         `json:"target"`
	SpecSource string         `json:"spec_source"`
	StartedAt  string         `json:"started_at"`
	FinishedAt string         `json:"finished_at"`
	Execution  string         `json:"execution"` // COMPLETE | PARTIAL
	Identities []string       `json:"identities"`
	Summary    map[string]int `json:"summary"`
	Checks     []Check        `json:"checks"`
}

const maxBodyScan = 256 << 10 // canary 扫描的响应体上限

type runner struct {
	cfg    *Config
	client *http.Client
	checks []Check
	hadErr bool
}

func isDeny(status int) bool { return status == 401 || status == 403 || status == 404 }
func is2xx(status int) bool  { return status >= 200 && status < 300 }

// do 执行一次带身份头的请求，返回状态码与（截断的）响应体。
func (r *runner) do(ctx context.Context, id Identity, method, url string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, "", err
	}
	headers, err := id.ResolvedHeaders()
	if err != nil {
		return 0, "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyScan))
	return resp.StatusCode, string(body), nil
}

func (r *runner) add(c Check) { r.checks = append(r.checks, c) }

// probe 一次请求并按回调判定。
func (r *runner) probe(ctx context.Context, op Operation, id Identity, probeKind, urlPath string,
	judge func(status int, body string) (Conclusion, string)) {

	full := strings.TrimRight(r.cfg.BaseURL, "/") + urlPath
	status, body, err := r.do(ctx, id, op.Method, full)
	ep := op.Method + " " + op.Path
	if err != nil {
		r.hadErr = true
		r.add(Check{Endpoint: ep, Identity: id.Name, Probe: probeKind,
			Expectation: r.cfg.expectationFor(op), Status: 0,
			Conclusion: ConclUnknown, Detail: "传输错误：" + err.Error()})
		return
	}
	concl, detail := judge(status, body)
	r.add(Check{Endpoint: ep, Identity: id.Name, Probe: probeKind,
		Expectation: r.cfg.expectationFor(op), Status: status,
		Conclusion: concl, Detail: detail})
}

// Run 执行全部探针并生成报告。
func Run(ctx context.Context, cfg *Config) (*Report, error) {
	ops, specSource, err := loadOperations(ctx, cfg)
	if err != nil {
		return nil, err
	}
	r := &runner{cfg: cfg, client: &http.Client{Timeout: time.Duration(cfg.TimeoutSecond) * time.Second}}
	started := time.Now().UTC()

	for _, op := range ops {
		if op.Method != http.MethodGet && !cfg.ProbeWrites {
			// 只读策略：写方法登记 NOT_RUN，绝不默认发出写请求。
			r.add(Check{Endpoint: op.Method + " " + op.Path, Identity: "-",
				Probe: "readonly-policy", Expectation: cfg.expectationFor(op),
				Conclusion: ConclNotRun,
				Detail:     "写方法在默认只读策略下跳过（probe_writes=true 且确认目标为夹具/隔离环境时才探测）"})
			continue
		}
		switch cfg.expectationFor(op) {
		case AccessPublic:
			r.runPublic(ctx, op)
		case AccessAdminOnly:
			r.runAdminOnly(ctx, op)
		case AccessOwnerOrAdmin:
			r.runOwnerOrAdmin(ctx, op)
		default: // authenticated
			r.runAuthenticated(ctx, op)
		}
	}

	if cfg.Replay != nil {
		r.runReplay(ctx, ops)
	}

	rep := &Report{
		ReportID:   "apiaudit-" + started.Format("20060102-150405"),
		Target:     cfg.BaseURL,
		SpecSource: specSource,
		StartedAt:  started.Format(time.RFC3339),
		FinishedAt: time.Now().UTC().Format(time.RFC3339),
		Execution:  "COMPLETE",
		Summary:    map[string]int{"PASS": 0, "FAIL": 0, "UNKNOWN": 0, "NOT_RUN": 0},
		Checks:     r.checks,
	}
	for _, id := range cfg.Identities {
		rep.Identities = append(rep.Identities, id.Name)
	}
	for _, c := range r.checks {
		rep.Summary[string(c.Conclusion)]++
	}
	if r.hadErr {
		rep.Execution = "PARTIAL"
	}
	return rep, nil
}

func loadOperations(ctx context.Context, cfg *Config) ([]Operation, string, error) {
	switch {
	case cfg.SpecFile != "":
		raw, err := os.ReadFile(cfg.SpecFile)
		if err != nil {
			return nil, "", err
		}
		ops, err := ParseOpenAPI(raw)
		return ops, "openapi-file:" + cfg.SpecFile, err
	case cfg.HARFile != "":
		raw, err := os.ReadFile(cfg.HARFile)
		if err != nil {
			return nil, "", err
		}
		ops, err := ParseHAR(raw)
		return ops, "har-file:" + cfg.HARFile, err
	default:
		// 从目标拉取 OpenAPI（无凭据的公开拉取；拉不到即报错，不猜测端点）。
		// spec_url 支持绝对 URL（手册口径）与相对路径（拼到 base_url 后）两种写法。
		url := cfg.SpecURL
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = strings.TrimRight(cfg.BaseURL, "/") + "/" + strings.TrimLeft(cfg.SpecURL, "/")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, "", err
		}
		resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
		if err != nil {
			return nil, "", fmt.Errorf("拉取 OpenAPI 失败: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, "", fmt.Errorf("拉取 OpenAPI 返回 %d", resp.StatusCode)
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if err != nil {
			return nil, "", err
		}
		ops, err := ParseOpenAPI(raw)
		return ops, "openapi-url:" + cfg.SpecURL, err
	}
}

// ---- 各访问模型的探针 ----

func (r *runner) runPublic(ctx context.Context, op Operation) {
	path, ok := instantiate(op.Path, firstOwns(r.cfg))
	if !ok {
		path = op.Path // 无参数或无样本：按模板原样请求，结论由状态码决定
	}
	for _, id := range r.cfg.Identities {
		if !id.IsAnonymous() {
			continue
		}
		r.probe(ctx, op, id, "direct", path, func(status int, _ string) (Conclusion, string) {
			switch {
			case is2xx(status):
				return ConclPass, "公开端点匿名可达"
			case isDeny(status):
				return ConclFail, fmt.Sprintf("声明为 public 的端点拒绝匿名访问（%d）", status)
			default:
				return ConclUnknown, fmt.Sprintf("非预期状态 %d", status)
			}
		})
		return
	}
	r.add(Check{Endpoint: op.Method + " " + op.Path, Identity: "-", Probe: "direct",
		Expectation: AccessPublic, Conclusion: ConclUnknown,
		Detail: "配置中没有匿名身份，无法验证公开可达性"})
}

func (r *runner) runAuthenticated(ctx context.Context, op Operation) {
	path, ok := instantiate(op.Path, firstOwns(r.cfg))
	if !ok {
		r.add(Check{Endpoint: op.Method + " " + op.Path, Identity: "-", Probe: "direct",
			Expectation: AccessAuthenticated, Conclusion: ConclUnknown,
			Detail: "路径参数无任何身份的 owns 样本，无法构造请求"})
		return
	}
	for _, id := range r.cfg.Identities {
		judgeAnon := func(status int, _ string) (Conclusion, string) {
			switch {
			case is2xx(status):
				return ConclFail, "匿名身份可达需认证端点"
			case isDeny(status):
				return ConclPass, "匿名被拒"
			default:
				return ConclUnknown, fmt.Sprintf("非预期状态 %d", status)
			}
		}
		judgeAuthed := func(status int, _ string) (Conclusion, string) {
			switch {
			case is2xx(status):
				return ConclPass, "已认证身份可达"
			case isDeny(status):
				return ConclUnknown, fmt.Sprintf("已认证身份被拒（%d）；可能为合法 RBAC，证据不足不判 FAIL", status)
			default:
				return ConclUnknown, fmt.Sprintf("非预期状态 %d", status)
			}
		}
		if id.IsAnonymous() {
			r.probe(ctx, op, id, "direct", path, judgeAnon)
		} else {
			r.probe(ctx, op, id, "direct", path, judgeAuthed)
		}
	}
}

func (r *runner) runAdminOnly(ctx context.Context, op Operation) {
	path, ok := instantiate(op.Path, firstOwns(r.cfg))
	if !ok {
		path = op.Path
	}
	for _, id := range r.cfg.Identities {
		var judge func(int, string) (Conclusion, string)
		switch {
		case id.Role == "admin":
			judge = func(status int, _ string) (Conclusion, string) {
				switch {
				case is2xx(status):
					return ConclPass, "管理员可达"
				case isDeny(status):
					return ConclUnknown, fmt.Sprintf("管理员被拒（%d），无法区分实现异常与样本问题", status)
				default:
					return ConclUnknown, fmt.Sprintf("非预期状态 %d", status)
				}
			}
		default:
			judge = func(status int, _ string) (Conclusion, string) {
				switch {
				case is2xx(status):
					return ConclFail, "非管理员身份可达管理员端点（垂直越权）"
				case isDeny(status):
					return ConclPass, "非管理员被拒"
				default:
					return ConclUnknown, fmt.Sprintf("非预期状态 %d", status)
				}
			}
		}
		r.probe(ctx, op, id, "direct", path, judge)
	}
}

func (r *runner) runOwnerOrAdmin(ctx context.Context, op Operation) {
	params := pathParams(op.Path)
	if len(params) == 0 {
		// 无路径参数的 owner 模型退化为 authenticated 语义。
		r.runAuthenticated(ctx, op)
		return
	}
	owners := []Identity{}
	for _, id := range r.cfg.Identities {
		if _, ok := instantiate(op.Path, id.Owns); ok {
			owners = append(owners, id)
		}
	}
	if len(owners) == 0 {
		r.add(Check{Endpoint: op.Method + " " + op.Path, Identity: "-", Probe: "self",
			Expectation: AccessOwnerOrAdmin, Conclusion: ConclUnknown,
			Detail: "没有任何身份提供路径参数 owns 样本，无法构造属主/跨主体探针"})
		return
	}
	// 自访问探针
	for _, owner := range owners {
		path, _ := instantiate(op.Path, owner.Owns)
		r.probe(ctx, op, owner, "self", path, func(status int, _ string) (Conclusion, string) {
			switch {
			case is2xx(status):
				return ConclPass, "属主可读自有资源"
			case isDeny(status):
				return ConclUnknown, fmt.Sprintf("属主被拒（%d），证据不足不判 FAIL", status)
			default:
				return ConclUnknown, fmt.Sprintf("非预期状态 %d", status)
			}
		})
	}
	// 跨主体探针：caller 用 owner 的参数访问，命中 owner.canary 即数据泄漏
	for _, owner := range owners {
		path, _ := instantiate(op.Path, owner.Owns)
		for _, caller := range r.cfg.Identities {
			if caller.Name == owner.Name {
				continue
			}
			ownerCopy, callerCopy := owner, caller
			r.probe(ctx, op, caller, "cross-owner:"+owner.Name, path,
				func(status int, body string) (Conclusion, string) {
					leaked := ownerCopy.Canary != "" && strings.Contains(body, ownerCopy.Canary)
					switch {
					case callerCopy.Role == "admin":
						if is2xx(status) {
							return ConclPass, "管理员跨主体访问（模型允许）"
						}
						return ConclUnknown, fmt.Sprintf("管理员跨主体被拒（%d）", status)
					case is2xx(status) && leaked:
						return ConclFail, fmt.Sprintf("跨主体读到 %s 的私有数据（canary 命中，水平越权）", ownerCopy.Name)
					case is2xx(status):
						return ConclUnknown, "跨主体返回 2xx 但未命中 canary；可能为脱敏/共享数据，证据不足"
					case isDeny(status):
						return ConclPass, "跨主体被拒"
					default:
						return ConclUnknown, fmt.Sprintf("非预期状态 %d", status)
					}
				})
		}
	}
}

// firstOwns 返回第一个带 owns 的身份样本（无参数端点时仅作占位）。
func firstOwns(cfg *Config) map[string]string {
	for _, id := range cfg.Identities {
		if len(id.Owns) > 0 {
			return id.Owns
		}
	}
	return map[string]string{}
}
