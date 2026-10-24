// 与 medaudit-server /api/v1 对接的 API 层（M6：全功能）。

export interface Health { status: string; version: string }

// M20 用户管理行
export interface UserRow {
  username: string
  disabled: boolean
  must_change_pwd: boolean
  created_at: string
  updated_at: string
}

// 本站医院（单院部署，初始化时给定；未初始化时 hospital_id 为空）
export interface SiteInfo { hospital_id: string; name: string }

// 规则启停记录（本站作用域；无记录 = 启用）
export interface RuleToggle {
  rule_id: string
  enabled: boolean
  reason: string
  updated_by: string
  updated_at: string
}

export interface Hospital { id: string; name: string; created_at: string }

export interface Asset {
  id: string
  hospital_id: string
  kind: string
  name: string
  endpoint: string | null
  labels?: string | null
}

export interface ConnConfig {
  engine: string
  host: string
  port: number
  user: string
  dbname?: string
  service?: string
  sslmode?: string
}

export interface AuditRunResult {
  bundle_id: string
  facts: number
  receipts: number
  evaluation: EvalSummary
  report_id: string
}

export interface BundleSummary {
  id: string
  plan_id: string
  hospital_id: string
  asset_id: string
  schema_version: string
  adapter: string
  execution: string
  fact_count: number
  receipt_count: number
  imported_at: string
}

export interface Finding {
  id: number
  bundle_id: string
  rule_id: string
  rule_version: string
  subject: string
  conclusion: string
  detail: string
  review_status: string
  created_at: string
}

export interface Rule {
  ID: string
  Version: string
  Name: string
  Target: string
  Description: string
  Requires: string[]
  Risk: string
  Remediation: string
}

/** 基线放行项（服务端 Go 结构体字段名，首字母大写）。 */
export interface ExemptAllow {
  Subject: string
  Kind: string
  Value: string
  Scope: string
  Reason?: string
}

export interface ExemptionPreview {
  supported: boolean
  rule_id: string
  subject: string
  target: string
  hospital_id: string
  allows: ExemptAllow[] | null
}

export interface ExemptResult {
  baseline_id: string
  target: string
  hospital_id: string
  added: ExemptAllow[]
  skipped_existing: number
}

export interface BaselineRow {
  id: string
  hospital_id: string
  target: string
  version: number
  spec: string
}

export interface EvalSummary {
  bundle_id: string
  total: number
  pass: number
  fail: number
  unknown: number
  not_applicable: number
  not_run: number
  findings_stored: number
}

export interface Fact {
  fact_id: string
  kind: string
  subject: string
  status: string
  source: string
  attributes?: Record<string, string>
  permission_path?: string[]
  scope?: string
}

export interface FactsPage {
  bundle_id: string
  total: number
  counts_by_kind: Record<string, number>
  facts: Fact[]
}

export interface RetestRow {
  id: number
  finding_id: number
  hospital_id: string
  bundle_id: string
  conclusion: string
  created_at: string
}

export interface RemediationRow {
  id: number
  finding_id: number
  hospital_id: string
  action: string
  status: string
  acted_by: string
  acted_at: string | null
  created_at: string
}

export interface ReportRow {
  id: string
  hospital_id: string
  plan_id: string
  bundle_id: string
  created_by: string
  created_at: string
  conclusion_summary?: Record<string, number>
}

export interface ApiAuditSummary {
  report_id: string
  target: string
  execution: string
  total: number
  pass_count: number
  fail_count: number
  unknown_count: number
  not_run_count: number
  imported_at: string
}

export interface ApiAuditCheck {
  probe: string
  endpoint: string
  identity: string
  expectation: string
  conclusion: string
  status: number
  detail: string
}

// ---- M8/M9/M10 扩展类型（按后端结构体逐字对齐） ----

export interface RemoteConfig {
  transport?: string
  host: string
  port?: number
  user: string
  server_url?: string
  host_key?: string
  mw_type?: string
  mw_home?: string
  services?: string
}

// parseRemote 解析资产 labels 中的远程推送配置；无 host/user 视为未登记。
export function parseRemote(a: Asset): RemoteConfig | null {
  if (!a.labels) return null
  try {
    const t = JSON.parse(a.labels)
    if (t && t.host && t.user) return t as RemoteConfig
  } catch { /* labels 非 JSON 时忽略 */ }
  return null
}

export interface RemoteAuditResult extends AuditRunResult {
  transport: string
  host_key_fingerprint?: string
}

export interface CorrelationSummary {
  report_id: string
  hospital_id: string
  bundle_ids: string[]
  path_count: number
  created_by?: string
  created_at: string
}

export interface CorrelationHop {
  from: string
  action: string
  to: string
  bundle_id: string
  evidence: string[]
}

export interface CorrelationDetail extends CorrelationSummary {
  result: {
    bundles: number
    nodes: number
    edges: number
    paths: { source: string; target: string; risk: string; hops: CorrelationHop[] }[]
  }
}

export interface EffectiveEntry {
  subject: string
  is_role: boolean
  roles: { role: string; path: string[]; evidence: string[]; activation?: string }[]
  privileges: { privilege: string; scope?: string; direct: boolean; via?: string[]; evidence: string[] }[]
}

export interface DriftItem {
  kind: string
  source: string
  subject: string
  category: string
  detail: string
}

export interface DriftReport {
  base_id: string
  compare_id: string
  asset_id: string
  adapter: string
  added: DriftItem[]
  removed: DriftItem[]
  added_total: number
  removed_total: number
  attention: number
}

export interface HospitalSummary {
  hospital_id: string
  assets: number
  bundles: number
  fail_total: number
  fail_open: number
  unknown_total: number
  corr_paths: number
  last_bundle_at: string
}

export interface ReportPathsSection {
  correlation_report_id: string
  generated_at: string
  bundle_ids: string[]
  nodes: number
  edges: number
  path_count: number
  paths: { source: string; target: string; risk: string; chain: string }[]
  note: string
}

export interface ReportDriftSection {
  base_id: string
  added_total: number
  removed_total: number
  attention: number
  added: DriftItem[]
  removed: DriftItem[]
  note: string
}

export interface RemediationScript {
  finding_id: number
  rule_id: string
  subject: string
  scope?: string
  precheck: string
  fix: string
  verify: string
  rollback: string
  note?: string
}

export interface ReportRemediationSection {
  fail_total: number
  generated: number
  stored: number
  scripts: RemediationScript[]
  note: string
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, init)
  if (!r.ok) {
    // M12：会话失效时通知 App 回到登录页（登录接口自身除外）
    if (r.status === 401 && path !== '/api/v1/auth/login') {
      window.dispatchEvent(new CustomEvent('medaudit:unauthorized'))
    }
    const text = await r.text()
    throw new Error(text.trim() || `请求 ${path} 失败：${r.status}`)
  }
  return (await r.json()) as T
}

function post<T>(path: string, body: unknown): Promise<T> {
  return req<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

export const api = {
  health: () => req<Health>('/api/v1/health'),
  site: () => req<SiteInfo>('/api/v1/site'),
  // M12 登录鉴权
  me: () => req<{ username: string; must_change_pwd?: boolean }>('/api/v1/auth/me'),
  login: (username: string, password: string) =>
    post<{ username: string }>('/api/v1/auth/login', { username, password }),
  logout: () => post('/api/v1/auth/logout', {}),
  changePassword: (old_password: string, new_password: string) =>
    post('/api/v1/auth/change-password', { old_password, new_password }),
  // M20 用户管理
  users: () => req<UserRow[]>('/api/v1/users'),
  createUser: (username: string, password: string) => post('/api/v1/users', { username, password }),
  resetUserPassword: (username: string, password: string) =>
    req(`/api/v1/users/${encodeURIComponent(username)}/password`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    }),
  setUserDisabled: (username: string, disabled: boolean) =>
    req(`/api/v1/users/${encodeURIComponent(username)}/disabled`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ disabled }),
    }),
  hospitals: () => req<Hospital[]>('/api/v1/hospitals'),
  createHospital: (id: string, name: string) => post('/api/v1/hospitals', { id, name }),
  assets: () => req<Asset[]>('/api/v1/assets'),
  createAsset: (a: Partial<Asset>) => post('/api/v1/assets', a),
  updateAsset: (id: string, body: { kind: string; name: string; endpoint: string | null; labels?: string | null }) =>
    req(`/api/v1/assets/${encodeURIComponent(id)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  deleteAsset: (id: string) =>
    req(`/api/v1/assets/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  ruleToggles: () => req<RuleToggle[]>('/api/v1/rule-toggles'),
  setRuleToggle: (body: { rule_id: string; enabled: boolean; reason?: string; updated_by?: string }) =>
    req('/api/v1/rule-toggles', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  runAudit: (body: { asset_id: string; password: string; baseline_id?: string; created_by?: string }) =>
    post<AuditRunResult>('/api/v1/audit/run', body),
  // M9 远程推送审计
  runRemoteAudit: (body: { asset_id: string; password: string; baseline_id?: string; created_by?: string }) =>
    post<RemoteAuditResult>('/api/v1/audit/run-remote', body),
  // M8 关联分析 / 有效权限 / 漂移 / 医院汇总
  correlations: () => req<CorrelationSummary[]>('/api/v1/correlations'),
  correlation: (id: string) => req<CorrelationDetail>(`/api/v1/correlations/${encodeURIComponent(id)}`),
  runCorrelation: (bundleIds: string[]) =>
    post<CorrelationDetail>('/api/v1/correlations', { bundle_ids: bundleIds }),
  bundleEffective: (id: string) => req<EffectiveEntry[]>(`/api/v1/bundles/${encodeURIComponent(id)}/effective`),
  bundleDrift: (id: string, against: string) =>
    req<DriftReport>(`/api/v1/bundles/${encodeURIComponent(id)}/drift?against=${encodeURIComponent(against)}`),
  hospitalSummaries: () => req<HospitalSummary[]>('/api/v1/summary/hospitals'),
  bundles: () => req<BundleSummary[]>('/api/v1/bundles'),
  uploadBundle: async (file: File) => {
    const r = await fetch('/api/v1/bundles', { method: 'POST', body: file })
    const data = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error((data && data.error) || `上传失败：${r.status}`)
    return data as { bundle_id: string; status: string; facts: number; receipts: number }
  },
  bundleFacts: (id: string, kind: string, offset: number, limit: number) =>
    req<FactsPage>(`/api/v1/bundles/${encodeURIComponent(id)}/facts?kind=${encodeURIComponent(kind)}&offset=${offset}&limit=${limit}`),
  evidenceUrl: (id: string) => `/api/v1/bundles/${encodeURIComponent(id)}/evidence`,
  findings: (bundleId: string) =>
    req<Finding[]>(`/api/v1/findings?bundle_id=${encodeURIComponent(bundleId)}`),
  evaluate: (bundleId: string, baselineId?: string) =>
    post<EvalSummary>('/api/v1/evaluations', { bundle_id: bundleId, baseline_id: baselineId || '' }),
  review: (findingId: number, body: { hospital_id: string; decision: string; comment: string; reviewer: string }) =>
    post(`/api/v1/findings/${findingId}/review`, body),
  retest: (findingId: number, bundleId: string) =>
    post<RetestRow>(`/api/v1/findings/${findingId}/retest`, { bundle_id: bundleId }),
  retests: (findingId: number) => req<RetestRow[]>(`/api/v1/findings/${findingId}/retests`),
  remediations: (findingId: number) => req<RemediationRow[]>(`/api/v1/findings/${findingId}/remediations`),
  addRemediation: (findingId: number, body: { action: string; status: string; acted_by: string }) =>
    post<RemediationRow>(`/api/v1/findings/${findingId}/remediations`, body),
  baselines: (hospitalId: string) =>
    req<BaselineRow[]>(`/api/v1/baselines?hospital_id=${encodeURIComponent(hospitalId)}`),
  createBaseline: (body: { id: string; hospital_id: string; target: string; allows: unknown[]; created_by: string }) =>
    post('/api/v1/baselines', body),
  exemptPreview: (findingId: number) =>
    post<ExemptionPreview>('/api/v1/baselines/exempt-preview', { finding_id: findingId }),
  exemptFinding: (body: { finding_id: number; baseline_id?: string; new_baseline_id?: string; reason?: string; created_by?: string }) =>
    post<ExemptResult>('/api/v1/baselines/exempt', body),
  removeBaselineAllow: (body: { baseline_id: string; subject: string; kind: string; value: string; scope: string }) =>
    post<{ status: string; removed: number }>('/api/v1/baselines/remove-allow', body),
  updateBaseline: (id: string, allows: unknown[]) =>
    req<{ status: string; id: string }>(`/api/v1/baselines/${encodeURIComponent(id)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ allows }),
    }),
  deleteBaseline: (id: string) =>
    req<{ status: string; id: string }>(`/api/v1/baselines/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  rules: () => req<Rule[]>('/api/v1/rules'),
  reports: () => req<ReportRow[]>('/api/v1/reports'),
  createReport: (body: { hospital_id: string; plan_id: string; bundle_id: string; created_by: string }) =>
    post<{ status: string; report_id: string }>('/api/v1/reports', body),
  getReport: (id: string) => req<Record<string, unknown>>(`/api/v1/reports/${encodeURIComponent(id)}`),
  reportDocxUrl: (id: string) => `/api/v1/reports/${encodeURIComponent(id)}/docx`,
  reportCsvUrl: (id: string) => `/api/v1/reports/${encodeURIComponent(id)}/csv`,
  apiAudits: () => req<ApiAuditSummary[]>('/api/v1/api-audits'),
  apiAuditDocxUrl: (id: string) => `/api/v1/api-audits/${encodeURIComponent(id)}/docx`,
  getApiAudit: (id: string) =>
    req<{ checks: ApiAuditCheck[]; summary?: Record<string, number>; target?: string; execution?: string }>(
      `/api/v1/api-audits/${encodeURIComponent(id)}`),
}
