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

## 会话重放探针（M31）

差分探测测权限设计对不对；重放探针测偷来的凭证好不好用，即会话失效
机制（登出、过期、改密、吊销）是否真实生效。探针不获取凭证，只重放
给定凭证；凭证走 identities 的 HeadersEnv，不落配置文件。

apicheck YAML 新增 `replay` 段（留空则不跑重放，行为与现版一致）：

```yaml
replay:
  sessions:
    - name: alice-logged-out
      identity: alice
      invalidated: logged_out  # logged_out | expired | password_changed | revoked
      note: "登出后捕获的会话"
  endpoints: []  # 留空 = 全部 GET 端点；也可指定 "GET /api/..." 清单
```

判定（保守，证据不足一律 UNKNOWN）：重放返回 2xx → FAIL（失效会话仍
被接受）；401/403/404 → PASS（失效会话被拒）；其他状态 / 传输错误 →
UNKNOWN；路径参数无 owns 样本 → UNKNOWN。写方法默认登记 NOT_RUN，
`probe_writes=true` 且确认目标为隔离环境时才发出。重放检查计入同一
报告的 Checks 与 Summary，上传与 Word 渲染路径不变。
