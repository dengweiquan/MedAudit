package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"medaudit/internal/apiaudit"
)

// runAPICheck 业务接口越权检测：apicheck -f <yml> [-o 报告.json] [-u 上传地址]
// 上传地址缺省读环境 MEDAUDIT_SERVER；输出缺省 apicheck-<时间>.json。
func runAPICheck(args []string) error {
	fs := flag.NewFlagSet("apicheck", flag.ContinueOnError)
	var configPath, out, upload string
	fs.StringVar(&configPath, "f", "", "越权检测配置文件（YAML）")
	fs.StringVar(&configPath, "config", "", "同 -f")
	fs.StringVar(&out, "o", "", "报告输出路径（缺省自动命名）")
	fs.StringVar(&out, "out", "", "同 -o")
	fs.StringVar(&upload, "u", "", "平台服务地址，报告生成后上传（缺省环境 MEDAUDIT_SERVER）")
	fs.StringVar(&upload, "upload", "", "同 -u")
	pos, err := splitPos(fs, args)
	if err != nil {
		return err
	}
	if configPath == "" && len(pos) > 0 {
		configPath = pos[0]
	}
	if configPath == "" {
		return fmt.Errorf("用法：apicheck -f <配置.yml> [-o 报告.json] [-u 上传地址]")
	}
	if out == "" {
		out = fmt.Sprintf("apicheck-%s.json", time.Now().UTC().Format("20060102-150405"))
	}
	if upload == "" {
		upload = os.Getenv("MEDAUDIT_SERVER")
	}
	cfg, err := apiaudit.LoadConfig(configPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	rep, err := apiaudit.Run(ctx, cfg)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		return err
	}
	fmt.Printf("越权检测完成：%d checks（PASS %d / FAIL %d / UNKNOWN %d / NOT_RUN %d），execution=%s → %s\n",
		len(rep.Checks), rep.Summary["PASS"], rep.Summary["FAIL"],
		rep.Summary["UNKNOWN"], rep.Summary["NOT_RUN"], rep.Execution, out)

	if upload != "" {
		url := strings.TrimRight(upload, "/") + "/api/v1/api-audits"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("上传报告失败: %w", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		fmt.Printf("上传结果：%d %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		if resp.StatusCode >= 300 {
			return fmt.Errorf("上传报告被拒：%d", resp.StatusCode)
		}
	}
	return nil
}
