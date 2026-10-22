# 业务接口越权检测（M4-1，2026-10-20）

## 设计

- 引擎 internal/apiaudit：多身份会话对同一端点做差分探测。
- 端点来源：OpenAPI 3（spec_url/spec_file）或 HAR（har_file，数值/UUID 段模板化为 {id}）。
- 访问期望模型：public / authenticated / admin_only / owner_or_admin。
- 跨主体探针靠 canary 判定：响应含属主 canary 即 FAIL（水平越权）；2xx 但无 canary → UNKNOWN（不判安全也不判泄漏）；非管理员 2xx 达管理端点 → FAIL（垂直越权）。
- 写方法默认只读策略：登记 NOT_RUN，绝不默认发出（probe_writes=true 仅在确认夹具/隔离目标时启用）。
- 凭据：配置中 headers_env 引用环境变量，不落配置与报告。

## 夹具

cmd/medaudit-fixture（127.0.0.1:19090）：已知坏用例（水平越权 /api/users/{id}、垂直越权 /api/admin/users）、已知好用例（/api/admin/stats 角色校验、/api/profile、公开 /api/public/health）、写端点 /api/notes。

## 实测（夹具）

- OpenAPI 路径：26 checks → PASS 19 / FAIL 6 / UNKNOWN 0 / NOT_RUN 1，6 条 FAIL 全部为植入漏洞，零误报。
- HAR 路径：/api/users/2 模板化为 /api/users/{id}（owns 需配 {id} 键），4 条水平越权 FAIL 全部命中。
- 报告经 POST /api/v1/api-audits 存档（migration 005），列表/明细可查。

## 边界（诚实说明）

- 同一身份只能看到自己的资源时，无法区分“接口有鉴权”与“后端静态返回”，靠 canary 命中才判 FAIL。
- 对象/资源 ID 的属主映射由配置 owns 提供，HAR 路径的 {id} 与 OpenAPI 参数名不一致时需在配置中对齐。
- 发现项的逐项复核（finding review）与报告导出集成是后续（M4-4）工作；当前报告以独立表存档可查。
