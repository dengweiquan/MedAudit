# M9 远程推送采集（2026-10-21，生产 0.9.0-m9）

## 做什么
Web 一键审计从数据库类扩展到 OS 与中间件：服务端把采集器推送到目标机执行，
回传事实包后走既有管线（导入→评估→报告）。OS/中间件页对登记了远程参数的资产
显示「远程审计」按钮；口令在弹窗输入，仅本次传输会话使用，永不落库/落盘/进日志（同 M6 模式）。

## 传输设计
- SSH（Linux，golang.org/x/crypto/ssh 口令认证）：采集器二进制经会话 stdin 流式推送到
  /tmp/medaudit-push-<随机>，执行后事实包 zip 经 SSH 取回，目录用后删除。
  全程不要求目标机能回连服务端。主机密钥：资产 labels 登记 host_key（SHA256 指纹）时严格校验；
  未登记时接受并在审计结果中回显实际指纹（TOFU 留痕）。
- WinRM（Windows，NTLM）：采集器 exe 约 14MB，WinRM 分片上传太慢，改由目标机凭一次性令牌
  从服务端拉取：GET /api/v1/agent/download?token=（令牌单次有效、5 分钟过期、进程内存存储）。
  事实包 zip 体积小，经 WinRM 以 Base64 分片取回。因此 Windows 资产必须登记 server_url
  （目标机可达的服务地址）；未登记时快速失败并明确提示。服务端需配置 Windows 采集器：
  环境变量 MEDAUDIT_COLLECTOR_WIN_BIN，或与服务端同目录的 medaudit-collector.exe。
- 编排：POST /api/v1/audit/run-remote {asset_id, password, baseline_id?, created_by?}，
  与 DB 一键审计共用串行锁与收尾管线（importEvaluateReport）。

## 资产登记（labels JSON，RemoteConfig）
{transport, host, port, user, server_url, host_key, mw_type, mw_home, services}
Web 登记表单（OS 页/中间件页）已提供对应字段；中间件 mw_home 也可由路径型 endpoint 推断。

## 验证（预发，生产库副本，未污染生产数据）
- SSH → kf03 Linux OS：134 事实（非 root 测试账号，权限不足项按既有语义记录），评估+报告生成，指纹回显。
- SSH → kf03 Nginx 夹具：植入弱配置命中 autoindex/plain_listener 等 FAIL（另有一条 run_as_root
  来自 kf03 本机真实运行的 nginx 主进程 root 身份，证据 pid 在案，非误报）。
- WinRM → win2019-test 域控 OS：1163 事实，含域组 role_edge 11 条（本地 19 + 域 11 = 30），约 29 秒全流程。
- WinRM → win2019-test IIS：精确复现 M7 植入的 6 条 FAIL。
- 回归：DB 一键审计（PG16）重构后正常（62 事实+报告）。
- 生产校验：版本 0.9.0-m9、规则 55、生产 8 包不变、令牌接口对无效令牌返回 403。

## 边界
- 推送的采集器与服务端同版本同架构（Linux amd64 / Windows amd64）。
- 采集器以登录账号身份在目标机运行，不提权；权限不足的事实记 permission_denied/PARTIAL。
- 生产服务绑定 127.0.0.1 时，Windows 推送的 server_url 需指向目标机可达的地址（部署决策，不在本里程碑改动）。
- 目标机残留：临时目录在流程结束时删除（SSH/WinRM 均已验证）；异常中断可能残留 medaudit-push-* 目录，可手动清理。
- kf03 上的预发测试账号 m9test 与 Nginx 夹具为一次性验证物，验证后已删除；证据见上。
