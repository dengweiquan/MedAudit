package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"medaudit/internal/collect/oshpux"
	"medaudit/internal/facts"
	"medaudit/internal/remote"
)

// hpux 子命令（M21）：HP-UX 权限采集。Go 无 HP-UX 目标平台，不推送
// 二进制——经 SSH 在目标机执行固定只读命令集，本地解析成事实包；
// --from-transcript 可从命令转录目录离线回放（夹具/现场留样）。

type hpuxSSHRunner struct {
	ctx context.Context
	cli *remote.SSHClient
}

func (r hpuxSSHRunner) Run(key string) (string, error) {
	cmd, ok := oshpux.Commands[key]
	if !ok {
		return "", fmt.Errorf("未知命令键 %s", key)
	}
	out, _, err := r.cli.Run(r.ctx, cmd)
	return string(out), err
}

func runHpux(args []string) error {
	// 形式：hpux <user@host[:port]> [资产id] | hpux -t <转录目录> [资产id]
	fs := flag.NewFlagSet("hpux", flag.ContinueOnError)
	var out, hospital, asset, plan, host, user, pwEnv, hostKey, transcript string
	var port int
	fs.StringVar(&out, "o", "", "事实包输出路径（默认按包 ID 命名）")
	fs.StringVar(&out, "out", "", "同 -o")
	fs.StringVar(&hospital, "H", "", "医院 ID（缺省环境 MEDAUDIT_HOSPITAL）")
	fs.StringVar(&hospital, "hospital", "", "同 -H")
	fs.StringVar(&asset, "asset", "", "资产 ID（或位置参数）")
	fs.StringVar(&plan, "p", "", "采集计划 ID")
	fs.StringVar(&plan, "plan", "", "同 -p")
	fs.StringVar(&host, "host", "", "目标机地址（SSH 模式，或位置参数 user@host）")
	fs.IntVar(&port, "port", 22, "SSH 端口")
	fs.StringVar(&user, "user", "", "SSH 用户（SSH 模式）")
	fs.StringVar(&pwEnv, "e", "MEDAUDIT_HPUX_PASSWORD", "口令来源环境变量名")
	fs.StringVar(&pwEnv, "password-env", "MEDAUDIT_HPUX_PASSWORD", "同 -e")
	fs.StringVar(&hostKey, "k", "", "登记的主机密钥 SHA256 指纹（空 = TOFU 并回显）")
	fs.StringVar(&hostKey, "host-key", "", "同 -k")
	fs.StringVar(&transcript, "t", "", "转录目录（每命令键一个 <键>.txt），离线回放")
	fs.StringVar(&transcript, "from-transcript", "", "同 -t")
	pos, err := splitPos(fs, args)
	if err != nil {
		return err
	}
	// 位置参数：SSH 模式第一个为 [user@]host[:port]，其后为资产 ID；转录模式第一个即资产 ID
	if transcript == "" && len(pos) > 0 {
		ep := pos[0]
		pos = pos[1:]
		if at := strings.IndexByte(ep, '@'); at > 0 {
			user = ep[:at]
			ep = ep[at+1:]
		}
		if c := strings.LastIndexByte(ep, ':'); c > 0 {
			if n, err := strconv.Atoi(ep[c+1:]); err == nil {
				host, port = ep[:c], n
			} else {
				host = ep
			}
		} else {
			host = ep
		}
	}
	if len(pos) > 0 && asset == "" {
		asset = pos[0]
	}
	if asset == "" {
		if host != "" {
			asset = "hpux-" + host
		} else {
			asset = "hpux-transcript"
		}
	}
	hospital = resolveHospital(hospital, "")

	var runner oshpux.Runner
	identity := "transcript"
	if transcript != "" {
		m := oshpux.MapRunner{}
		for _, key := range oshpux.SortedKeys() {
			raw, err := os.ReadFile(filepath.Join(transcript, key+".txt"))
			if err == nil {
				m[key] = string(raw)
			}
		}
		runner = m
	} else {
		if host == "" || user == "" {
			return fmt.Errorf("SSH 模式需目标端点 user@host（或改用 -t 转录目录）")
		}
		pw := os.Getenv(pwEnv)
		if pw == "" {
			return fmt.Errorf("口令须经环境变量 %s 提供（与 db 子命令同一纪律，不交互输入）", pwEnv)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer cancel()
		cli, err := remote.DialSSH(ctx, host, port, user, pw, hostKey)
		if err != nil {
			return fmt.Errorf("SSH 连接失败: %w", err)
		}
		defer cli.Close()
		fmt.Fprintf(os.Stderr, "主机密钥指纹: %s\n", cli.Fingerprint)
		runner = hpuxSSHRunner{ctx: ctx, cli: cli}
		identity = "ssh:" + user + "@" + host
	}

	b, err := oshpux.Collect(runner, oshpux.Config{
		HospitalID: hospital, AssetID: asset, PlanID: plan,
		CollectorIdentity: identity, CollectorVersion: version,
	})
	if err != nil {
		return err
	}
	outPath := out
	if outPath == "" {
		outPath = b.BundleID + ".zip"
	}
	if err := facts.WriteZip(outPath, b); err != nil {
		return err
	}
	fmt.Printf("已写出 %s（%d 条事实，执行 %s，收据 %d 条）\n", outPath, len(b.Facts), b.Execution, len(b.Receipts))
	return nil
}
