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

## 合规挂接（M4-4，医疗-12）

- 四条规则（各立一条，不用笼统通过项包住引擎；Target 均为 api，Version 均为 1）：
  `api.anon_protected_access`（未认证访问受保护接口）、`api.user_admin_access`（普通身份访问管理员接口）、
  `api.cross_owner_access`（跨所有者访问）、`api.invalidated_session_replay`（凭据失效后重放）。
  映射：医疗-12（草稿框架）+ 等保 8.1.4.2 a/d 与 8.1.4.1 b（对应关系；非 API 包上四规则均为 NA，
  不影响既有等保报告）。
- 事实契约（`internal/apiaudit/facts.go` ToFacts）：报告 checks → api_check 事实；
  探针事实（Source api.audit）+ 正向对照事实（Source api.control，由同报告差分 2xx 派生，不新增探针）。
  结论语义：FAIL 只在引擎已拿到确切证据时出现（水平越权要求 canary 命中；2xx 无 canary 仍 UNKNOWN）；
  PASS 要求每个通过探针都有同端点对照（公开/已认证/管理员/属主/端点可达），否则拒答可能是 404，
  一律 UNKNOWN；全部 NOT_RUN（写方法只读策略）→ UNKNOWN；无此类探针 → 不适用。
  未认证与垂直的分流靠报告的匿名身份清单：管理员端点匿名 FAIL 归未认证规则，
  已认证或清单缺失（老报告）的 FAIL 归垂直规则（匿名本就是非管理员子集）；清单缺失时
  未认证规则对无法归属的 FAIL 不误判 PASS（返回 UNKNOWN）。
- 报告绑定（`apiaudit/v1`）：apicheck 配置可选 `hospital_id`/`asset_id`；服务端存档时校验
  资产存在且归属该医院（否则拒绝上传），统计由 checks 重算（不信任客户端 Summary）。
  合规判定端点 `GET /api/v1/api-audits/{id}/compliance`（需登录）：绑定 + 资产库核实通过才评估，
  否则条款为 unknown（老格式、无绑定、资产未核实皆如此，历史报告不自动纳入通过）。
  上传信任边界：POST 上传须持有效会话（采集器以超级令牌 `-t` / `MEDAUDIT_TOKEN` 登录换会话后上传，
  无令牌时拒绝上传；服务端记录 upload_authenticated）。未认证上传的历史报告只保留查阅，
  即使绑定一致也不作可信合规依据（条款 unknown）。注意：同 report_id 的认证重传只会返回
  duplicate，不升级信任——须重新运行审计生成新 report_id 后以认证方式上传，再复评。
  （未新建按资产划分的机器身份模型，复用现有超级令牌/会话体系；资产绑定校验仍限制可上传资产。）
  负向探针与正向对照：探针事实中 PASS+2xx 恒为授权方自己的成功（只证明端点存在，不计入负向覆盖），
  负向探针通过恒为拒答（4xx）；只配置授权方身份时负向覆盖为零，规则为 UNKNOWN，绝不判 PASS。
  未认证规则的匿名证据只认明确标记 anonymous=true 的探针：普通用户的拒答不得充当匿名探针，
  老报告缺标记时无法归属（UNKNOWN）；覆盖按端点核对，A 端点完成不能掩盖 B 端点的缺口。
  未运行项是覆盖缺口（只读策略跳过的写方法、非公开端点重放未探测），公开端点重放跳过不算缺口；
  全部探针均为公开端点重放跳过时（如纯公开端点报告），重放规则判不适用（NA），
  不是通过，也不是未确认——公开端点无需重放探测。
- 重放探针：公开端点跳过（NOT_RUN；公开端点接受失效会话不是漏洞）；重放 PASS 要求
  同端点差分 2xx 对照（证明端点存在）。重放会话的有效性由操作员在配置中声明，本规则不验证该声明。
- Web：报告页业务接口报告行有「合规判定」按钮（调合规端点，展示医疗-12 条款与四规则结论、
  对照与未绑定原因）；对象页归属以 asset_id 绑定优先、目标地址匹配回退；医院过滤同样绑定优先。
- 夹具验收（2026-11-03，隔离应用）：27 checks（PASS 18 / FAIL 7 / UNKNOWN 0 / NOT_RUN 2），
  合规判定 bound=true、条款 fail：未认证 pass，垂直 fail 2（admin/users 任意登录可达），
  水平 fail 2（跨主体 canary 命中），重放 fail 3（夹具令牌无失效机制，属预期）；对照五类齐全。

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
