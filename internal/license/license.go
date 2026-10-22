// Package license 实现维讯源码许可证的版本显示与授权版门控。
//
// 许可证格式为统一 v2（weixun-lic 统一授权台口径）：JSON 字段含
// product（本产品固定 "medaudit"），签名规范串键序固定为
// product, licensee, hosts, issued, expires, serial, activation_id,
// host_key_fingerprint；验签时 product 不符按签名失败处理。
//
// 两种构建：免费版（默认，Edition=free）与授权版（构建时
// -ldflags "-X medaudit/internal/license.Edition=licensed"）。
// 授权版在「产生新数据」的操作（审计执行/采集产包）前校验许可证：
// 文件默认 /etc/medaudit.license，环境变量 MEDAUDIT_LICENSE 可覆盖；
// Ed25519 验签（公钥嵌入）；过期 30 天内为宽限期（放行+警告），
// 剩余 ≤30 天临期提醒（放行），其余不可用情形拦截。
// 文案与 altrootdisk 现行口径一致（中英随语言环境切换）。
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Edition 构建版本类型：free（默认）或 licensed（授权版构建）。
var Edition = "free"

// PublicKeyB64 许可方 Ed25519 公钥（base64）。私钥已于 2026-10-22
// 移交统一授权台 weixun-lic 保管（本机副本已删除），本产品侧仅持公钥验签。
const PublicKeyB64 = "WpzDCluvYnz6lsGBQclpHJojP+LrMiAYYX1J7CJPbZE="

const (
	ContactEmail  = "sales@xmweixun.com"
	DefaultPath   = "/etc/medaudit.license"
	EnvPath       = "MEDAUDIT_LICENSE"
	GraceDays     = 30
	RemindDays    = 30
	CopyrightLine = "Copyright (c) 2026 厦门维讯信息科技有限公司 (Xiamen Weixun Information Technology Co., Ltd.)"
)

// ProductName 本产品的许可证 product 值（统一格式 v2）。
const ProductName = "medaudit"

// File 许可证文件（JSON，统一格式 v2）。签名字段名为 sig，内容为对
// 其余字段规范串（见 Payload）的 Ed25519 签名（base64）。
type File struct {
	Product            string `json:"product"`
	Licensee           string `json:"licensee"`
	Hosts              int    `json:"hosts"`
	Issued             string `json:"issued"`  // YYYY-MM-DD
	Expires            string `json:"expires"` // YYYY-MM-DD
	Serial             string `json:"serial"`
	ActivationID       string `json:"activation_id,omitempty"`
	HostKeyFingerprint string `json:"host_key_fingerprint,omitempty"`
	Signature          string `json:"sig"` // base64
}

// canonicalPayload 签名载荷的规范形式（统一标准，2026-10-22 钉死，
// 以授权台 weixun-lic 与 altrootdisk 的 internal/license 为唯一母版）：
// 紧凑 JSON，键序固定为 product, licensee, hosts, issued, expires,
// serial, activation_id, host_key_fingerprint；预留字段恒出现（空串），
// 字符串按 Go encoding/json 紧凑编码，取 UTF-8 字节签/验。
type canonicalPayload struct {
	Product            string `json:"product"`
	Licensee           string `json:"licensee"`
	Hosts              int    `json:"hosts"`
	Issued             string `json:"issued"`
	Expires            string `json:"expires"`
	Serial             string `json:"serial"`
	ActivationID       string `json:"activation_id"`
	HostKeyFingerprint string `json:"host_key_fingerprint"`
}

// Payload 待签名的规范串（签发与验签共用）。
func (f *File) Payload() string {
	b, err := json.Marshal(canonicalPayload{
		Product:            f.Product,
		Licensee:           f.Licensee,
		Hosts:              f.Hosts,
		Issued:             f.Issued,
		Expires:            f.Expires,
		Serial:             f.Serial,
		ActivationID:       f.ActivationID,
		HostKeyFingerprint: f.HostKeyFingerprint,
	})
	if err != nil {
		return ""
	}
	return string(b)
}

// Path 许可证文件路径：环境变量优先，否则默认路径。
func Path() string {
	if p := os.Getenv(EnvPath); p != "" {
		return p
	}
	return DefaultPath
}

// English 语言环境是否为英文（LC_ALL > LC_MESSAGES > LANG，前缀 en）。
func English() bool {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" {
			return strings.HasPrefix(strings.ToLower(v), "en")
		}
	}
	return false
}

// 拦截状态短语（四选一）。
const (
	ReasonNotFound = iota + 1
	ReasonMalformed
	ReasonBadSignature
	ReasonExpired
)

func reasonText(code int, en bool) string {
	switch code {
	case ReasonNotFound:
		if en {
			return "license file not found"
		}
		return "未找到许可证文件"
	case ReasonMalformed:
		if en {
			return "the license file is malformed"
		}
		return "许可证文件格式损坏"
	case ReasonBadSignature:
		if en {
			return "license signature verification failed"
		}
		return "许可证签名验证失败"
	case ReasonExpired:
		if en {
			return "the license has expired and the grace period has ended"
		}
		return "许可证已过期且超出宽限期"
	}
	return ""
}

// Status 许可证评估结果。
type Status struct {
	Licensed bool   // 授权版构建
	Usable   bool   // 可用（有效/临期/宽限均可用）
	File     *File  // 验签通过时的许可证内容
	Reason   int    // 不可用原因（Reason* 常量）
	DaysLeft int    // 距到期天数（负数为已过期天数）
	Expires  string // 到期日 YYYY-MM-DD
	GraceEnd string // 宽限期截止日 YYYY-MM-DD（过期时）
	Path     string
}

// Evaluate 评估当前许可证状态（授权版才真正读文件；免费版恒可用）。
func Evaluate(now time.Time) Status {
	st := Status{Path: Path()}
	if Edition != "licensed" {
		st.Usable = true
		return st
	}
	st.Licensed = true
	raw, err := os.ReadFile(st.Path)
	if err != nil {
		st.Reason = ReasonNotFound
		return st
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil || f.Licensee == "" || f.Expires == "" {
		st.Reason = ReasonMalformed
		return st
	}
	// 统一格式 v2 产品校验：他产品许可证（含签名对他产品有效者）
	// 一律按签名验证失败处理。
	if f.Product != ProductName {
		st.Reason = ReasonBadSignature
		return st
	}
	pub, err := base64.StdEncoding.DecodeString(PublicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		st.Reason = ReasonBadSignature
		return st
	}
	sig, err := base64.StdEncoding.DecodeString(f.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), []byte(f.Payload()), sig) {
		st.Reason = ReasonBadSignature
		return st
	}
	exp, err := time.Parse("2006-01-02", f.Expires)
	if err != nil {
		st.Reason = ReasonMalformed
		return st
	}
	st.File = &f
	st.Expires = f.Expires
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	st.DaysLeft = int(exp.Sub(today).Hours() / 24)
	if st.DaysLeft < 0 {
		st.GraceEnd = exp.AddDate(0, 0, GraceDays).Format("2006-01-02")
		if -st.DaysLeft > GraceDays {
			st.Reason = ReasonExpired
			return st
		}
	}
	st.Usable = true
	return st
}

// VersionBlock 版本信息输出：首行「程序名 版本号」（供脚本解析），
// 其后著作权/署名/授权联系/版本类型；授权版验签可用时加「授权给」行。
func VersionBlock(prog, version string, now time.Time) string {
	en := English()
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", prog, version)
	b.WriteString(CopyrightLine + "\n")
	if en {
		b.WriteString("Project direction: Deng WeiQuan\n")
		fmt.Fprintf(&b, "Commercial licensing: %s\n", ContactEmail)
	} else {
		b.WriteString("项目规划：邓伟权\n")
		fmt.Fprintf(&b, "商业授权联系：%s\n", ContactEmail)
	}
	st := Evaluate(now)
	if !st.Licensed {
		if en {
			b.WriteString("Edition: Free (free for personal and non-production use)\n")
		} else {
			b.WriteString("版本类型：免费版（个人与非生产用途免费）\n")
		}
		return b.String()
	}
	if en {
		b.WriteString("Edition: Licensed\n")
	} else {
		b.WriteString("版本类型：授权版\n")
	}
	if st.Usable && st.File != nil {
		if en {
			fmt.Fprintf(&b, "Licensed to: %s (expires %s)\n", st.File.Licensee, st.Expires)
		} else {
			fmt.Fprintf(&b, "授权给：%s（有效期至 %s）\n", st.File.Licensee, st.Expires)
		}
	}
	return b.String()
}

// ReasonString 拦截原因短语（随语言环境本地化）。
func ReasonString(code int) string { return reasonText(code, English()) }

// Gate 「产生新数据」操作前的门控。免费版直接放行；授权版不可用时
// 返回拦截文案错误；临期/宽限返回提醒文案（放行）。
func Gate(now time.Time) (warnings []string, err error) {
	st := Evaluate(now)
	if !st.Licensed {
		return nil, nil
	}
	en := English()
	if !st.Usable {
		reason := reasonText(st.Reason, en)
		if en {
			return nil, fmt.Errorf("This build is the licensed edition, but no usable license is available (%s). Place the license file at %s and retry; for commercial licensing contact %s", reason, st.Path, ContactEmail)
		}
		return nil, fmt.Errorf("本程序为授权版构建，但许可证不可用（%s）。请将许可证文件放到 %s 后重试；商业授权联系 %s", reason, st.Path, ContactEmail)
	}
	// 可用：临期提醒 / 宽限期警告
	if st.DaysLeft < 0 {
		if en {
			warnings = append(warnings, fmt.Sprintf("The commercial license expired on %s and is now in its grace period (until %s); contact %s to renew as soon as possible", st.Expires, st.GraceEnd, ContactEmail))
		} else {
			warnings = append(warnings, fmt.Sprintf("商业许可证已于 %s 过期，现处于宽限期（至 %s），请尽快联系 %s 续期", st.Expires, st.GraceEnd, ContactEmail))
		}
	} else if st.DaysLeft <= RemindDays {
		if en {
			warnings = append(warnings, fmt.Sprintf("Note: the commercial license expires on %s (%d days left); contact %s to renew in time", st.Expires, st.DaysLeft, ContactEmail))
		} else {
			warnings = append(warnings, fmt.Sprintf("提醒：商业许可证将于 %s 到期（剩余 %d 天），请尽早联系 %s 续期", st.Expires, st.DaysLeft, ContactEmail))
		}
	}
	return warnings, nil
}
