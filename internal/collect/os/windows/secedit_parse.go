package windows

import (
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ParseSeceditInf 解析 secedit /export 导出的 .inf 文本，返回 [System Access] 段的键值对。
// 键统一小写（如 passwordcomplexity）；值去首尾空白与首尾引号。
// 编码接受 UTF-16LE（含/不含 BOM）与 UTF-8/ASCII；无 [System Access] 段时返回空 map，不报错。
// 注意：只解析稳定的英文键，不解析任何本地化文案。
func ParseSeceditInf(data []byte) map[string]string {
	text := decodeSecedit(data)
	out := map[string]string{}
	inSection := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSpace(line[1 : len(line)-1])
			inSection = strings.EqualFold(name, "System Access")
			continue
		}
		if !inSection {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"`)
		if k == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// decodeSecedit 把 secedit 导出字节解码为字符串。
func decodeSecedit(data []byte) string {
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return decodeUTF16LE(data[2:])
	}
	if len(data) >= 2 && len(data)%2 == 0 && looksUTF16LE(data) {
		return decodeUTF16LE(data)
	}
	if utf8.Valid(data) {
		return string(data)
	}
	return string(data)
}

// looksUTF16LE 启发式判断无 BOM 数据是否为 UTF-16LE：抽查前 200 字节，
// 奇数位为 0 的比例超过 80% 时判定为 UTF-16LE（ASCII 内容的典型形态）。
func looksUTF16LE(data []byte) bool {
	n := len(data)
	if n > 200 {
		n = 200
	}
	if n < 2 {
		return false
	}
	zero := 0
	for i := 1; i < n; i += 2 {
		if data[i] == 0 {
			zero++
		}
	}
	return zero*5 > (n/2)*4
}

func decodeUTF16LE(b []byte) string {
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u16 = append(u16, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return string(utf16.Decode(u16))
}
