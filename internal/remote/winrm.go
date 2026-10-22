package remote

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/masterzen/winrm"
)

// WinRMClient 一次 WinRM（NTLM）连接。
type WinRMClient struct {
	client *winrm.Client
}

// DialWinRM 以 NTLM 认证建连（5985/http 为实验室与内网常见部署；
// 端口由调用方给出，默认 5985）。
func DialWinRM(host string, port int, user, password string) (*WinRMClient, error) {
	endpoint := winrm.NewEndpoint(host, port, false, false, nil, nil, nil, 0)
	params := winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
	client, err := winrm.NewClientWithParameters(endpoint, user, password, params)
	if err != nil {
		return nil, fmt.Errorf("WinRM 客户端创建失败: %w", err)
	}
	return &WinRMClient{client: client}, nil
}

// RunPS 执行一段 PowerShell，返回 stdout/stderr/退出码。
// 脚本尾部可用 `exit $LASTEXITCODE` 把原生命令退出码透传出来。
func (c *WinRMClient) RunPS(ctx context.Context, script string) (stdout, stderr string, code int, err error) {
	return c.client.RunPSWithContextWithString(ctx, script, "")
}

func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// Download 从 url 拉取文件到远程路径（采集器 exe 约 14MB，WinRM 分片传文件太慢，
// 改由目标机从服务端一次性令牌地址拉取）。
func (c *WinRMClient) Download(ctx context.Context, url, remotePath string) (int64, error) {
	script := fmt.Sprintf(
		"$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; "+
			"Invoke-WebRequest -Uri %s -OutFile %s -UseBasicParsing; (Get-Item %s).Length",
		psQuote(url), psQuote(remotePath), psQuote(remotePath))
	out, se, code, err := c.RunPS(ctx, script)
	if err != nil {
		return 0, fmt.Errorf("远程下载失败: %w", err)
	}
	if code != 0 {
		return 0, fmt.Errorf("远程下载失败（退出码 %d）: %s", code, strings.TrimSpace(se))
	}
	n, perr := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if perr != nil {
		return 0, fmt.Errorf("远程下载长度解析失败: %q", strings.TrimSpace(out))
	}
	return n, nil
}

// FetchFileBase64 分片取回远程文件：先取 Base64 总长，再逐片 Substring 拼接解码。
// 单片 40000 字符（远低于 WinRM 信封上限）；maxBytes 超限报错不截断。
func (c *WinRMClient) FetchFileBase64(ctx context.Context, remotePath string, maxBytes int) ([]byte, error) {
	head := fmt.Sprintf("$s=[Convert]::ToBase64String([IO.File]::ReadAllBytes(%s)); $s.Length", psQuote(remotePath))
	out, se, code, err := c.RunPS(ctx, head)
	if err != nil {
		return nil, fmt.Errorf("读取远程文件失败: %w", err)
	}
	if code != 0 {
		return nil, fmt.Errorf("读取远程文件失败（退出码 %d）: %s", code, strings.TrimSpace(se))
	}
	total, perr := strconv.Atoi(strings.TrimSpace(out))
	if perr != nil {
		return nil, fmt.Errorf("远程文件长度解析失败: %q", strings.TrimSpace(out))
	}
	if total > (maxBytes/3+2)*4 {
		return nil, fmt.Errorf("远程文件 %s 超过 %d 字节上限", remotePath, maxBytes)
	}
	const chunk = 40000
	var sb strings.Builder
	sb.Grow(total)
	for off := 0; off < total; off += chunk {
		n := chunk
		if off+n > total {
			n = total - off
		}
		script := fmt.Sprintf("$s=[Convert]::ToBase64String([IO.File]::ReadAllBytes(%s)); $s.Substring(%d, %d)",
			psQuote(remotePath), off, n)
		part, se, code, err := c.RunPS(ctx, script)
		if err != nil {
			return nil, fmt.Errorf("分片取回失败（偏移 %d）: %w", off, err)
		}
		if code != 0 {
			return nil, fmt.Errorf("分片取回失败（偏移 %d，退出码 %d）: %s", off, code, strings.TrimSpace(se))
		}
		sb.WriteString(strings.TrimSpace(part))
	}
	raw, err := base64.StdEncoding.DecodeString(sb.String())
	if err != nil {
		return nil, fmt.Errorf("远程文件 Base64 解码失败: %w", err)
	}
	if len(raw) > maxBytes {
		return nil, fmt.Errorf("远程文件 %s 超过 %d 字节上限", remotePath, maxBytes)
	}
	return raw, nil
}

// RunCollector 在远程目录执行采集器 exe 并透传退出码；
// stdout/stderr 由调用方用于错误定位（只取尾部）。
func (c *WinRMClient) RunCollector(ctx context.Context, exePath string, args ...string) (stdout, stderr string, code int, err error) {
	var sb strings.Builder
	sb.WriteString("& " + psQuote(exePath))
	for _, a := range args {
		sb.WriteString(" " + psQuote(a))
	}
	sb.WriteString("; exit $LASTEXITCODE")
	return c.RunPS(ctx, sb.String())
}

// MkDirTemp 在 %TEMP% 下建 medaudit-push-<suffix> 目录并返回完整路径。
func (c *WinRMClient) MkDirTemp(ctx context.Context, suffix string) (string, error) {
	dir := `C:\Windows\Temp\medaudit-push-` + suffix
	out, se, code, err := c.RunPS(ctx, fmt.Sprintf(
		"New-Item -ItemType Directory -Force -Path %s | Out-Null; Write-Output %s", psQuote(dir), psQuote(dir)))
	if err != nil {
		return "", fmt.Errorf("远程建目录失败: %w", err)
	}
	if code != 0 {
		return "", fmt.Errorf("远程建目录失败（退出码 %d）: %s", code, strings.TrimSpace(se))
	}
	_ = out
	return dir, nil
}

// RemoveDir 尽力清理远程目录（失败不报错，由调用方忽略）。
func (c *WinRMClient) RemoveDir(ctx context.Context, dir string) {
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, _, _, _ = c.RunPS(ctx2, "Remove-Item -Recurse -Force "+psQuote(dir)+" -ErrorAction SilentlyContinue")
}
