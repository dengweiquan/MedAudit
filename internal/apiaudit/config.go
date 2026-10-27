// Package apiaudit 业务接口越权检测引擎（M4-1）。
// 以多身份会话对同一端点做差分探测：水平越权（跨主体读他人资源）、
// 垂直越权（低权身份达管理员端点）。判定保守：证据不足一律 UNKNOWN，
// 绝不把“没测出来”写成“安全”。
package apiaudit

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// AccessKind 端点期望访问模型。
type AccessKind string

const (
	AccessPublic        AccessKind = "public"         // 匿名可达
	AccessAuthenticated AccessKind = "authenticated"  // 任意已认证身份
	AccessAdminOnly     AccessKind = "admin_only"     // 仅管理员
	AccessOwnerOrAdmin  AccessKind = "owner_or_admin" // 资源属主或管理员
)

// Identity 一个探测身份（会话）。匿名身份不带任何头。
type Identity struct {
	Name       string            `yaml:"name"`
	Role       string            `yaml:"role"` // admin | user | ""（匿名）
	Headers    map[string]string `yaml:"headers"`
	HeadersEnv map[string]string `yaml:"headers_env"` // 头名 -> 环境变量名（凭据不落配置）
	// Owns 该身份拥有的路径参数样本，如 user_id: "2"（用于自访问与跨主体探针）。
	Owns map[string]string `yaml:"owns"`
	// Canary 只应出现在该身份自有资源响应里的标记串（如邮箱），
	// 跨主体探针在他人响应中发现它即判定数据泄漏。
	Canary string `yaml:"canary"`
}

// ResolvedHeaders 合并字面量头与环境变量头（环境变量优先，便于轮换凭据）。
func (id Identity) ResolvedHeaders() (map[string]string, error) {
	out := map[string]string{}
	for k, v := range id.Headers {
		out[k] = v
	}
	for k, env := range id.HeadersEnv {
		v := os.Getenv(env)
		if v == "" {
			return nil, fmt.Errorf("身份 %s 的头 %s：环境变量 %s 未设置", id.Name, k, env)
		}
		out[k] = v
	}
	return out, nil
}

// IsAnonymous 无凭据身份。
func (id Identity) IsAnonymous() bool {
	return len(id.Headers) == 0 && len(id.HeadersEnv) == 0
}

// Expectation 端点期望（按模板路径匹配；Method 空 = 任意方法）。
type Expectation struct {
	Method string     `yaml:"method"`
	Path   string     `yaml:"path"`
	Access AccessKind `yaml:"access"`
}

// Config 引擎配置。
type Config struct {
	BaseURL       string        `yaml:"base_url"`
	SpecURL       string        `yaml:"spec_url"` // 与 SpecFile/HARFile 三选一
	SpecFile      string        `yaml:"spec_file"`
	HARFile       string        `yaml:"har_file"`
	Identities    []Identity    `yaml:"identities"`
	Expectations  []Expectation `yaml:"expectations"`
	ProbeWrites   bool          `yaml:"probe_writes"` // 默认 false：写方法只登记 NOT_RUN
	TimeoutSecond int           `yaml:"timeout_seconds"`
	Replay        *ReplayConfig `yaml:"replay"` // M31：会话重放探针；留空则不跑重放
}

// LoadConfig 读取 YAML 配置并做基本校验。
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("解析配置: %w", err)
	}
	if strings.TrimSpace(c.BaseURL) == "" {
		return nil, fmt.Errorf("base_url 必填")
	}
	if c.SpecURL == "" && c.SpecFile == "" && c.HARFile == "" {
		return nil, fmt.Errorf("spec_url / spec_file / har_file 必须给出一个")
	}
	if len(c.Identities) == 0 {
		return nil, fmt.Errorf("至少需要一个身份（通常含匿名）")
	}
	seen := map[string]bool{}
	for _, id := range c.Identities {
		if id.Name == "" || seen[id.Name] {
			return nil, fmt.Errorf("身份名为空或重复: %q", id.Name)
		}
		seen[id.Name] = true
	}
	for _, e := range c.Expectations {
		switch e.Access {
		case AccessPublic, AccessAuthenticated, AccessAdminOnly, AccessOwnerOrAdmin:
		default:
			return nil, fmt.Errorf("端点 %s 的 access 非法: %q", e.Path, e.Access)
		}
	}
	if c.TimeoutSecond <= 0 {
		c.TimeoutSecond = 10
	}
	if err := c.validateReplay(); err != nil {
		return nil, err
	}
	return &c, nil
}

// expectationFor 查找端点的期望；无显式声明时默认 authenticated。
func (c *Config) expectationFor(op Operation) AccessKind {
	for _, e := range c.Expectations {
		if e.Path == op.Path && (e.Method == "" || strings.EqualFold(e.Method, op.Method)) {
			return e.Access
		}
	}
	return AccessAuthenticated
}
