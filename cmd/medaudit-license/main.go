// medaudit-license — 许可方签发工具（不随产品包分发）。
//
// 用法：
//
//	medaudit-license -licensee 某医院 -hosts 1 -days 365 [-serial S] [-issued YYYY-MM-DD]
//	                 [-key 私钥文件] [-out medaudit.license]
//
// 私钥文件为 Ed25519 seed 的 base64 单行文本（0600 保管）；
// 缺省读环境变量 MEDAUDIT_LICENSE_KEY 指向的文件，再缺省
// /root/.medaudit/license-ed25519.key。
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"medaudit/internal/license"
)

func main() {
	licensee := flag.String("licensee", "", "被授权方名称（必填）")
	hosts := flag.Int("hosts", 1, "授权站点数")
	days := flag.Int("days", 365, "有效期天数（自签发日）")
	serial := flag.String("serial", "", "序列号（缺省按日期+随机生成）")
	issued := flag.String("issued", "", "签发日 YYYY-MM-DD（缺省今天）")
	keyPath := flag.String("key", "", "私钥文件（缺省见说明）")
	out := flag.String("out", "medaudit.license", "输出许可证文件")
	activation := flag.String("activation", "", "预留 activation_id")
	fingerprint := flag.String("fingerprint", "", "预留 host_key_fingerprint")
	flag.Parse()

	if *licensee == "" {
		fmt.Fprintln(os.Stderr, "错误：-licensee 必填")
		os.Exit(1)
	}
	kp := *keyPath
	if kp == "" {
		kp = os.Getenv("MEDAUDIT_LICENSE_KEY")
	}
	if kp == "" {
		kp = "/root/.medaudit/license-ed25519.key"
	}
	raw, err := os.ReadFile(kp)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误：读私钥失败：", err)
		os.Exit(1)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintln(os.Stderr, "错误：私钥格式不对（应为 Ed25519 seed 的 base64）")
		os.Exit(1)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	now := time.Now()
	iss := now.Format("2006-01-02")
	if *issued != "" {
		iss = *issued
	}
	issT, err := time.Parse("2006-01-02", iss)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误：-issued 格式应为 YYYY-MM-DD")
		os.Exit(1)
	}
	ser := *serial
	if ser == "" {
		ser = fmt.Sprintf("MA-%s-%04d", issT.Format("20060102"), now.UnixNano()%10000)
	}
	f := license.File{
		Product:  license.ProductName,
		Licensee: *licensee, Hosts: *hosts, Issued: iss,
		Expires: issT.AddDate(0, 0, *days).Format("2006-01-02"),
		Serial:  ser, ActivationID: *activation, HostKeyFingerprint: *fingerprint,
	}
	f.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(f.Payload())))
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误：", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, append(data, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "错误：写出失败：", err)
		os.Exit(1)
	}
	fmt.Printf("已签发：%s（被授权方 %s，站点 %d，%s 至 %s，序列号 %s）\n",
		*out, f.Licensee, f.Hosts, f.Issued, f.Expires, f.Serial)
}
