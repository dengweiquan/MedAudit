// 会话重放探针（M31）：用已捕获的会话凭证重放，检验会话失效机制
// 是否真实生效。探针不获取凭证，只重放给定凭证；判定保守，证据不足
// 一律 UNKNOWN。写方法默认不发（只读策略，与差分探针一致）。
package apiaudit

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Invalidation 会话失效条件。
type Invalidation string

const (
	InvalidLoggedOut       Invalidation = "logged_out"       // 已登出
	InvalidExpired         Invalidation = "expired"          // 已过期
	InvalidPasswordChanged Invalidation = "password_changed" // 已改密
	InvalidRevoked         Invalidation = "revoked"          // 已吊销
)

// ReplaySession 一次重放探针：用指定身份的截获会话凭证重放。
type ReplaySession struct {
	Name        string      `yaml:"name"`        // 会话名（报告 Identity 字段）
	Identity    string      `yaml:"identity"`    // 引用 identities 中的身份名
	Invalidated Invalidation `yaml:"invalidated"` // 失效条件
	Note        string      `yaml:"note"`        // 失效背景说明（附加到 Detail）
}

// ReplayConfig 重放探针配置。Endpoints 留空 = 全部 GET 端点。
type ReplayConfig struct {
	Sessions  []ReplaySession `yaml:"sessions"`
	Endpoints []string        `yaml:"endpoints"` // "GET /api/..." 清单
}

// validateReplay 校验重放配置：身份引用存在、失效条件合法、端点格式合法。
func (c *Config) validateReplay() error {
	if c.Replay == nil {
		return nil
	}
	byName := map[string]bool{}
	for _, id := range c.Identities {
		byName[id.Name] = true
	}
	for _, s := range c.Replay.Sessions {
		if s.Name == "" {
			return fmt.Errorf("重放会话名为空")
		}
		if !byName[s.Identity] {
			return fmt.Errorf("重放会话 %s 引用的身份 %q 不存在", s.Name, s.Identity)
		}
		switch s.Invalidated {
		case InvalidLoggedOut, InvalidExpired, InvalidPasswordChanged, InvalidRevoked:
		default:
			return fmt.Errorf("重放会话 %s 的 invalidated 非法: %q", s.Name, s.Invalidated)
		}
	}
	for _, ep := range c.Replay.Endpoints {
		parts := strings.SplitN(strings.TrimSpace(ep), " ", 2)
		if len(parts) != 2 || parts[0] == "" || !strings.HasPrefix(parts[1], "/") {
			return fmt.Errorf("重放端点格式非法（应为 \"METHOD /path\"）: %q", ep)
		}
	}
	return nil
}

// replayOps 选出重放目标端点：指定清单精确匹配（方法不区分大小写），
// 留空则取全部 GET 端点。
func (c *Config) replayOps(ops []Operation) []Operation {
	if c.Replay == nil || len(c.Replay.Endpoints) == 0 {
		out := []Operation{}
		for _, op := range ops {
			if op.Method == http.MethodGet {
				out = append(out, op)
			}
		}
		return out
	}
	want := map[string]bool{}
	for _, ep := range c.Replay.Endpoints {
		parts := strings.SplitN(strings.TrimSpace(ep), " ", 2)
		want[strings.ToUpper(parts[0])+" "+parts[1]] = true
	}
	out := []Operation{}
	for _, op := range ops {
		if want[strings.ToUpper(op.Method)+" "+op.Path] {
			out = append(out, op)
		}
	}
	return out
}

// replayProbe 一次重放请求并判定（与 probe 同口径，Identity 记会话名，
// 以区分同一身份的多个失效会话）。
func (r *runner) replayProbe(ctx context.Context, op Operation, id Identity, s ReplaySession, probeKind, urlPath, note string) {
	full := strings.TrimRight(r.cfg.BaseURL, "/") + urlPath
	status, _, err := r.do(ctx, id, op.Method, full)
	ep := op.Method + " " + op.Path
	if err != nil {
		r.hadErr = true
		r.add(Check{Endpoint: ep, Identity: s.Name, Probe: probeKind,
			Expectation: r.cfg.expectationFor(op), Status: 0,
			Conclusion: ConclUnknown, Detail: "传输错误：" + err.Error()})
		return
	}
	var concl Conclusion
	var detail string
	switch {
	case is2xx(status):
		concl, detail = ConclFail, fmt.Sprintf("失效会话（%s）仍被接受%s", s.Invalidated, note)
	case isDeny(status):
		concl, detail = ConclPass, fmt.Sprintf("失效会话（%s）被拒%s", s.Invalidated, note)
	default:
		concl, detail = ConclUnknown, fmt.Sprintf("非预期状态 %d%s", status, note)
	}
	r.add(Check{Endpoint: ep, Identity: s.Name, Probe: probeKind,
		Expectation: r.cfg.expectationFor(op), Status: status,
		Conclusion: concl, Detail: detail})
}

// runReplay 执行全部重放探针，结果计入同一报告。
func (r *runner) runReplay(ctx context.Context, ops []Operation) {
	cfg := r.cfg
	targets := cfg.replayOps(ops)
	byName := map[string]Identity{}
	for _, id := range cfg.Identities {
		byName[id.Name] = id
	}
	for _, s := range cfg.Replay.Sessions {
		id, ok := byName[s.Identity]
		if !ok {
			r.add(Check{Endpoint: "-", Identity: s.Name, Probe: "replay:" + string(s.Invalidated),
				Conclusion: ConclUnknown, Detail: fmt.Sprintf("引用身份 %q 不存在", s.Identity)})
			continue
		}
		probeKind := "replay:" + string(s.Invalidated)
		note := ""
		if strings.TrimSpace(s.Note) != "" {
			note = "（" + s.Note + "）"
		}
		for _, op := range targets {
			if op.Method != http.MethodGet && !cfg.ProbeWrites {
				// 只读策略：写方法登记 NOT_RUN，绝不默认发出写请求。
				r.add(Check{Endpoint: op.Method + " " + op.Path, Identity: s.Name,
					Probe: probeKind, Expectation: cfg.expectationFor(op),
					Conclusion: ConclNotRun,
					Detail:     "写方法在默认只读策略下跳过（probe_writes=true 且确认目标为夹具/隔离环境时才探测）"})
				continue
			}
			path, ok := instantiate(op.Path, id.Owns)
			if !ok {
				r.add(Check{Endpoint: op.Method + " " + op.Path, Identity: s.Name,
					Probe: probeKind, Expectation: cfg.expectationFor(op),
					Conclusion: ConclUnknown,
					Detail:     "路径参数无该身份的 owns 样本，无法构造重放请求"})
				continue
			}
			r.replayProbe(ctx, op, id, s, probeKind, path, note)
		}
	}
}
