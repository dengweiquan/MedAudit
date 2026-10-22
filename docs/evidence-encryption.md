# 证据加密存储（M4-3b，2026-10-20）

方案要求“加密文件存储”。此前的事实包上传后只保留解析 JSON（fact_bundles.bundle，明文），
原始 zip 证据无处可查。现改为：上传的原始 zip 以 AES-256-GCM 加密存入
fact_bundle_evidence（迁移 004），同时回填 fact_bundles.evidence_digest。

## 设计

- blob 格式：MAE1 | key_version uint16 BE | nonce 12B | GCM ciphertext（含 tag）
- 密钥环：当前版本加密；全部历史版本均可解密（支持轮换后旧证据仍可验）
- 环境变量：MEDAUDIT_EVIDENCE_KEY（base64 32B，当前）、MEDAUDIT_EVIDENCE_KEY_VERSION（默认 1）、MEDAUDIT_EVIDENCE_KEY_V<n>（历史，仅解密）
- 未配置密钥时证据加密禁用（导入照常、证据不落库，启动日志明示）；密钥装配失败则服务端直接退出，避免静默降级
- 下载后服务端复核 SHA-256；摘要不一致视为完整性失败（HTTP 500）

## 接口

- GET /api/v1/bundles/{id}/evidence → 解密返回原始 zip（application/zip，附 X-Evidence-SHA256 头）
- 加密功能启用前导入的老包：HTTP 404（明确告知），不伪造

## 实测（2026-10-20 13:10，bundle-mysql-20261020-050928）

- fact_bundle_evidence：key_version=1，sha256 与原 zip 一致，blob 头 MAE1+0001
- 密文不含 zip 明文头（PK0304 未出现）
- 下载回传与原包逐字节一致（sha256 对得上）
- 老包（bundle-mysql-20261019-081750）→ 404
- 密钥文件：/root/.medaudit/evidence.env（600），启动脚本自动载入
