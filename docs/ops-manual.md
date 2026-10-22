# MedAudit V1 运维手册

## 1. 组件

| 组件 | 二进制 | 运行位置 |
|------|--------|----------|
| 管理服务 | medaudit-server | 中心服务器（Linux） |
| 采集器 | medaudit-collector（Linux）/ medaudit-collector.exe（Windows） | 被核查目标 |
| 平台库 | SQLite（单文件，server 内嵌驱动） | 中心服务器 |
| 前端 | web/dist（由 server 静态托管） | 随 server |

## 2. 安装

```bash
tar xzf medaudit-0.1.0-m3.tar.gz
cd medaudit-0.1.0-m3
sudo bash install.sh
# 平台库为本地 SQLite 文件 /opt/medaudit/data/medaudit.db，server 首次启动自动建库并执行内嵌迁移，无需单独安装数据库
# （可选）证据加密：创建 /etc/medaudit/evidence.env（600）：MEDAUDIT_EVIDENCE_KEY=<base64 32B 密钥>、MEDAUDIT_EVIDENCE_KEY_VERSION=1
sudo systemctl enable --now medaudit-server
```

## 3. 采集流程

```bash
# Linux 目标
./medaudit-collector os --out /tmp/os.zip --hospital h-xxx --asset host-01 --plan plan-1

# Windows 目标（管理员 PowerShell）
.\medaudit-collector.exe os --out C:\Temp\os.zip --hospital h-xxx --asset winhost-01 --plan plan-1

# 数据库目标（密码只经环境变量）
export MYSQL_PASS='***'
./medaudit-collector db --engine mysql --config mysql.yml --out /tmp/db.zip
# mysql.yml: host/port/user/service, password_env: MYSQL_PASS

# 校验与上传
./medaudit-collector bundle verify --in /tmp/os.zip
./medaudit-collector bundle upload --in /tmp/os.zip --server http://central:8080
```

## 4. 评估与复核

1. 上传事实包后：`POST /api/v1/evaluations {bundle_id, baseline_id?}`
2. 查看问题：`GET /api/v1/findings?bundle_id=...`（或前端结果页）
3. 人工复核：`POST /api/v1/findings/{id}/review {decision: confirmed|false_positive|exception, reviewer}`
4. 生成报告：`POST /api/v1/reports {hospital_id, plan_id, bundle_id}`

## 5. 基线管理

- `POST /api/v1/baselines {id, hospital_id, target, allows:[{subject,kind,value,scope,reason}]}`
- 基线只豁免技术结论，不改写事实包。

## 6. 备份与恢复

- 平台库（SQLite 单文件）每日备份：在线执行 VACUUM INTO 生成一致性备份文件（或停写窗口内整体复制数据文件及 -wal/-shm），保留 30 天。
- 恢复：将备份文件放到 MEDAUDIT_PLATFORM_DB 指向的路径后启动 server；恢复后核对 PRAGMA integrity_check 与关键业务计数。
- 事实包 zip 为不可变证据，独立归档；加密证据密文随平台库一并备份。

## 7. 常见问题

| 现象 | 排查 |
|------|------|
| 采集执行 PARTIAL | 查 receipts 的 error_stage，多为目标权限不足（permission_denied），按最小只读授权补齐 |
| Oracle 连接失败 | 确认网络可达与监听端口、服务名与口令正确（ORA-01017 为口令错误） |
| Windows 采集器报 oracle 不支持 | 预期行为；Oracle 采集用 Linux 采集器连远程实例 |
| 评估 UNKNOWN 偏多 | 前置事实缺失，检查采集收据是否为 denied/truncated |

## 8. 安全红线

- 禁止生产接入、禁止生产权限变更。
- 禁止 SET ROLE / EXECUTE AS 等身份冒充验证。
- 不读取业务表数据，只读权限元数据。
- DB 密码只经环境变量/secret，不进日志、事实包与代码库。
