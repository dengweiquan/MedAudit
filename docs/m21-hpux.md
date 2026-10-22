# M21 HP-UX 支持（0.23.0-m21，2026-10-22）

按阶段一评估（docs/m21-hpux-eval.md，用户 2026-10-22 批准）实施。

形态：Go 无 HP-UX 目标平台，不推送二进制。采集 = SSH 远程命令集
（13 条固定只读命令）→ 本地按 6 模板解析成标准事实包。两个入口
共用同一解析路径（internal/collect/oshpux）：
- 服务端：Web/ctl「远程审计」对 os-hpux 资产走 SSH 命令通道
  （platform.RunRemoteAudit 分支），后接同一导入-评估-报告管线；
- 工程师本地：medaudit-collector hpux --host/--user（口令经
  --password-env，缺省 MEDAUDIT_HPUX_PASSWORD）或
  --from-transcript <dir> 转录回放（每命令键一个 <键>.txt）。

模板 6：hpux.identity（passwd/group/logins/swlist 摘要）、
hpux.auth_policy（口令存储三态 trusted/shadow/standard +
/etc/default/security + kctune executable_stack）、hpux.sudo_rbac
（sudoers + RBAC 存在性）、hpux.inetd、hpux.startup_perm
（inetd.conf/init.d/rc.config.d 的 ls -ld）、hpux.setuid_files
（find 有界扫描）。事实类型全复用（identity/role_edge/
account_config/service_config/file_perm），无新类型。

规则 6（规则总数 59 → 65）：os.hpux.multiple_uid0、
weak_password_store（普通模式）、inetd_risky_service、
writable_service_file、setuid_unexpected（内置厂商集合 + 基线
钩子）、sudo_all（含 NOPASSWD 形态，对应 Linux 两条）。基线/启停/
报告/复检按 target 自动复用；kind os-hpux 归操作系统类。

验证（实验室无 HP-UX 真机，以转录夹具 + 通道代偿）：
- 金值单测（internal/collect/oshpux/golden_test.go）：植入转录
  六规则精确命中（1/1/3/1/1/1 共 8 条）、干净转录全 PASS、两包
  均 COMPLETE。测试曾抓到一个真 bug：sudoers 行把主机规格误作
  授权主体，已修正（主体取 '=' 前首 token 起、末 token 为主机）。
- 预发全链：转录产包 → ctl import → evaluate（植入 8 FAIL/干净
  0）→ report Word 正常（含 hpux 问题明细）。
- SSH 通道冒烟：以 kf7 本机为代偿目标（一次性账号 m21test，验后
  删除）走服务端远程审计：89 事实/6 收据、评估与报告自动完成、
  主机密钥 TOFU 回显。Linux 目标上 HP-UX 专有命令缺失使个别模板
  PARTIAL——即真机缺失项的诚实呈现，不影响通道结论。

遗留：真实 HP-UX 主机实采（11i v3）待用户提供可达主机或试点
现场时补验；命令回显的版本差异以 11i v3 为准。weak_password_store
当前判普通模式一态；aging 细粒度检查（shadow/trusted 下 aging
全关）留待真机样本校准后补。
