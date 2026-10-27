// Package remote 实现 M9 的远程推送传输层：
// SSH（Linux）与 WinRM（Windows）。仅做传输与远程执行，不理解事实包内容。
package remote

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHClient 一次 SSH 会话。Fingerprint 为服务端主机密钥的 SHA256 指纹
// （OpenSSH 格式 "SHA256:..."），连接建立后可读。
type SSHClient struct {
	conn        *ssh.Client
	Fingerprint string
}

// DialSSH 口令认证建连。expectedFP 非空时严格校验主机密钥指纹；
// 为空时接受并把实际指纹记入 Fingerprint（TOFU 留痕，由调用方回显给用户）。
func DialSSH(ctx context.Context, host string, port int, user, password, expectedFP string) (*SSHClient, error) {
	c := &SSHClient{}
	cfg := &ssh.ClientConfig{
		User:    user,
		Auth:    []ssh.AuthMethod{ssh.Password(password)},
		Timeout: 20 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fp := ssh.FingerprintSHA256(key)
			c.Fingerprint = fp
			if expectedFP != "" && !strings.EqualFold(fp, expectedFP) {
				return fmt.Errorf("主机密钥指纹不匹配：登记 %s，实际 %s", expectedFP, fp)
			}
			return nil
		},
	}
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	d := net.Dialer{Timeout: 20 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("连接 %s 失败: %w", addr, err)
	}
	sc, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("SSH 握手/认证失败: %w", err)
	}
	c.conn = ssh.NewClient(sc, chans, reqs)
	return c, nil
}

func (c *SSHClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Run 执行一条远程命令，返回 stdout/stderr；命令非零退出时 err 非空且带退出状态。
func (c *SSHClient) Run(ctx context.Context, cmd string) (stdout, stderr []byte, err error) {
	sess, err := c.conn.NewSession()
	if err != nil {
		return nil, nil, err
	}
	defer sess.Close()
	var outBuf, errBuf bytes.Buffer
	sess.Stdout = &outBuf
	sess.Stderr = &errBuf
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		c.Close()
		return outBuf.Bytes(), errBuf.Bytes(), ctx.Err()
	}
	return outBuf.Bytes(), errBuf.Bytes(), err
}

// PutReader 把 r 的内容流式写入远程文件并设置权限（如 "700"）。
func (c *SSHClient) PutReader(ctx context.Context, r io.Reader, remotePath, perm string) error {
	sess, err := c.conn.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = r
	var errBuf bytes.Buffer
	sess.Stderr = &errBuf
	done := make(chan error, 1)
	go func() { done <- sess.Run("cat > " + shellQuote(remotePath)) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		c.Close()
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("写入远程文件失败: %v（%s）", err, strings.TrimSpace(errBuf.String()))
	}
	if perm != "" {
		if _, se, err := c.Run(ctx, "chmod "+perm+" "+shellQuote(remotePath)); err != nil {
			return fmt.Errorf("chmod 失败: %v（%s）", err, strings.TrimSpace(string(se)))
		}
	}
	return nil
}

// GetFile 读取远程文件内容（上限 maxBytes，超出报错，不截断伪装完整）。
func (c *SSHClient) GetFile(ctx context.Context, remotePath string, maxBytes int64) ([]byte, error) {
	out, se, err := c.Run(ctx, "cat "+shellQuote(remotePath))
	if err != nil {
		return nil, fmt.Errorf("读取远程文件失败: %v（%s）", err, strings.TrimSpace(string(se)))
	}
	if int64(len(out)) > maxBytes {
		return nil, fmt.Errorf("远程文件 %s 超过 %d 字节上限", remotePath, maxBytes)
	}
	return out, nil
}
