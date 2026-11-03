package facts

import "regexp"

// RedactSecrets 脱敏失败原因原文：连接串口令、token、密钥类键值不得进入事实包与报告。
// 只替换秘密值本身（保留键名与错误结构），避免驱动报错把 DSN/连接串原文带入 bundle。
// 覆盖：password/pwd/token/secret/api_key 类键值、URL 用户信息（user:pass@）、Bearer 令牌。
var (
	redactKV     = regexp.MustCompile(`(?i)(password|passwd|pwd|token|secret|api[_-]?key)(\s*[:=]\s*)([^\s;,'"]+)`)
	redactURL    = regexp.MustCompile(`(://[^:/\s]+:)([^@\s]+)(@)`)
	redactBearer = regexp.MustCompile(`(?i)(Bearer\s+)([^\s]+)`)
)

// RedactSecrets 对 s 脱敏；空串原样返回。
func RedactSecrets(s string) string {
	if s == "" {
		return s
	}
	s = redactKV.ReplaceAllString(s, `${1}${2}***`)
	s = redactURL.ReplaceAllString(s, `${1}***${3}`)
	s = redactBearer.ReplaceAllString(s, `${1}***`)
	return s
}
