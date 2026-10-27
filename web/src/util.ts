import { api, type ApiAuditSummary, type BundleSummary, type Finding, type SiteInfo } from './api'

// loadSite 读取本站医院（单院部署初始化给定），全应用缓存一份。
let sitePromise: Promise<SiteInfo> | null = null
export function loadSite(): Promise<SiteInfo> {
  if (!sitePromise) {
    sitePromise = api.site().catch(() => ({ hospital_id: '', name: '' }))
  }
  return sitePromise
}
import { kindCategory, type CategoryKey } from './categories'
import { reviewerName } from './store'

// latestRunFindings 取一个事实包最新一轮评估落库的问题行。
// 评估落库是追加式的（同一包可多次评估）；一轮落库内部时间连续
// （逐条插入，间隔毫秒级），轮次之间通常相隔分钟以上——按 120 秒
// 间隙聚类取最后一簇。早期用「最大时间戳往前 1.5 秒」切分对大包
// 失效（一轮落库可达几十秒，只切到尾巴，会把 FAIL 误算为 0）。
export function latestRunFindings(rows: Finding[]): Finding[] {
  if (!rows.length) return rows
  const ts = (s: string) => Date.parse(s.replace(' ', 'T'))
  const sorted = [...rows].sort((a, b) => ts(a.created_at) - ts(b.created_at))
  let start = sorted.length - 1
  for (let i = sorted.length - 1; i > 0; i--) {
    if (ts(sorted[i].created_at) - ts(sorted[i - 1].created_at) > 120_000) break
    start = i - 1
  }
  return sorted.slice(start)
}

// 报告表问题数（M37-fix-5，M37-fix2-1 修正）：只按报告快照的 findings 计算，
// 不取包的实时问题，否则重新评估或改基线后历史报告行的数字会变。
// 注意快照 findings 来自 ListFindings，含该包所有评估轮次的结果（不是一轮），
// 故先按 latestRunFindings 取最新一轮（120 秒间隙聚类，与复检/最新问题同口径），
// 再过滤结论为不通过（FAIL）的项，按规则风险分级。
// 口径差异说明：服务端 compliance_report.go 的 latestRun 是「同一 created_at
// 为一轮」；但 DB 时间戳只到秒，一轮落库可达几十秒时它只取最后一秒的行，
// 会漏算大包（前端早年用最大时间戳往前 1.5 秒切分就踩过这个坑），故此处
// 不用服务端口径，用前端已有的 latestRunFindings。
export function countSnapshotRisks(findings: Finding[], riskOf: (ruleId: string) => string): { high: number; medium: number; low: number; other: number } {
  const c = { high: 0, medium: 0, low: 0, other: 0 }
  for (const f of latestRunFindings(findings)) {
    if (f.conclusion !== 'FAIL') continue
    const r = riskOf(f.rule_id).toLowerCase()
    if (r === 'high') c.high++
    else if (r === 'medium') c.medium++
    else if (r === 'low') c.low++
    else c.other++
  }
  return c
}

export function latestFail(rows: Finding[]): Finding[] {
  return latestRunFindings(rows).filter(f => f.conclusion === 'FAIL')
}

// bundleCategory 事实包归类：优先资产登记类型，其次适配器前缀。
export function bundleCategory(b: BundleSummary, kindByAsset: Map<string, string>): CategoryKey | 'unknown' {
  const kind = kindByAsset.get(b.asset_id)
  if (kind) {
    const c = kindCategory(kind)
    if (c !== 'unknown') return c
  }
  if (b.adapter.startsWith('db-')) return 'db'
  if (b.adapter.startsWith('os-')) return 'os'
  if (b.adapter.startsWith('mw-')) return 'mw'
  if (b.adapter === 'api') return 'api'
  return 'unknown'
}

// latestBundleOf 取同一对象导入时间最晚的包。服务端按 imported_at DESC 返回，
// 直接取末尾会拿到最旧的包（M37-1.1 同类 Bug），故此处显式按时间取最大。
export function latestBundleOf(bundles: BundleSummary[], assetId: string): BundleSummary | undefined {
  let best: BundleSummary | undefined
  for (const b of bundles) {
    if (b.asset_id !== assetId) continue
    if (!best || b.imported_at.localeCompare(best.imported_at) > 0 ||
      (b.imported_at === best.imported_at && b.id.localeCompare(best.id) > 0)) best = b
  }
  return best
}

export interface ComparePair { old: BundleSummary; new: BundleSummary }

// comparePair 取同一对象按导入时间升序的最后两次：old=上次，new=本次。
// 服务端按 imported_at DESC 返回，直接取末尾会把新旧颠倒（M37-1.1），故此处显式排序。
// 首页结论（M37-fix-4）：未审计对象不计为通过；只有全部对象都审计过且
// 都没有问题，才说「全部对象检查通过」。
export function buildConclusion(scope: string, total: number, unaudited: number, problems: number, high: number): string {
  if (total === 0) return '暂无审计对象'
  if (problems === 0 && unaudited === 0) return '全部对象检查通过'
  const parts = [`${scope} ${total} 个对象`]
  if (unaudited > 0) parts.push(`${unaudited} 个未审计`)
  if (problems > 0) parts.push(`${problems} 个有问题`)
  let s = parts.join('，')
  if (problems > 0) s += `；高风险 ${high} 项待整改。`
  else s += '。'
  return s
}

export function comparePair(bundles: BundleSummary[], assetId: string): ComparePair | null {
  const list = bundles.filter(b => b.asset_id === assetId)
    .sort((a, b) => a.imported_at.localeCompare(b.imported_at) || a.id.localeCompare(b.id))
  if (list.length < 2) return null
  return { old: list[list.length - 2], new: list[list.length - 1] }
}

export function bundlesOfAsset(bundles: BundleSummary[], assetId: string): BundleSummary[] {
  return bundles.filter(b => b.asset_id === assetId)
}

export type HospitalProgressStatus = 'none' | 'partial' | 'open' | 'clear'

// hospitalProgressStatus 医院整改进度状态（M37-fix2-5）：
// 已审计对象里只要有问题就显示「整改中」，未审计数由调用方在同一格补充
// 「另有 N 个未审计」；完全没有问题、但有未审计对象时才显示「部分未审计」。
// 此前部分未审计分支排在有问题分支之前，部分未审计会盖住整改中。
export function hospitalProgressStatus(
  total: number, audited: number, fail: number,
): { status: HospitalProgressStatus; unaudited: number } {
  const unaudited = total - audited
  if (audited === 0) return { status: 'none', unaudited }
  if (fail > 0) return { status: 'open', unaudited }
  if (unaudited > 0) return { status: 'partial', unaudited }
  return { status: 'clear', unaudited }
}

// filterApiReports 按医院过滤业务接口报告（M37-fix2-4）：
// 已匹配到登记对象的，按对象所属医院过滤；未匹配的只在「全部医院」视图
// 下显示，选定医院时不显示（此前未过滤，他院已匹配报告会以目标地址形式
// 漏进本院视图，未匹配报告也会出现在选定医院视图里）。
export function filterApiReports(
  reports: ApiAuditSummary[],
  assetByEndpoint: Map<string, { hospital_id: string }>,
  hospitalId: string,
): ApiAuditSummary[] {
  if (!hospitalId) return reports
  return reports.filter(r => assetByEndpoint.get(r.target)?.hospital_id === hospitalId)
}

// loadBundlesByAssets 按对象逐个取全部包（复检候选，M37-fix2-2）：
// 单个对象取包失败时跳过该对象，不影响其他对象；此前 Promise.all 任一
// 失败就清空全部，整页复检不可用。
export async function loadBundlesByAssets(
  assetIds: string[],
  fetchFn: (assetId: string) => Promise<BundleSummary[]>,
): Promise<BundleSummary[]> {
  const lists = await Promise.allSettled(assetIds.map(fetchFn))
  return lists.flatMap(r => r.status === 'fulfilled' ? r.value : [])
}

// exportLatestReport 为事实包生成报告并直接下载 Word（客户主路径）。
export async function exportLatestReport(b: BundleSummary): Promise<string> {
  const created = await api.createReport({
    hospital_id: b.hospital_id, plan_id: b.plan_id, bundle_id: b.id,
    created_by: reviewerName() || 'web',
  })
  const a = document.createElement('a')
  a.href = api.reportDocxUrl(created.report_id)
  a.download = ''
  document.body.appendChild(a)
  a.click()
  a.remove()
  return created.report_id
}

// baselineKindLabel 基线放行项「种类」的中文名（与规则口径对应）。
export function baselineKindLabel(kind: string): string {
  const m: Record<string, string> = {
    privilege: '权限', role: '角色', identity: '身份', sudo: 'sudo 授权',
    tls: '传输加密', service: '服务', setuid: 'setuid 文件', deployment: '部署',
    hba: '连接规则', profile: '概要文件项', config: '配置项', variable: '全局变量',
    settings: '设置', role_attr: '角色属性',
  }
  return m[kind] ?? kind
}

// fmtLocal 把服务端时间字符串渲染为浏览器本地时区时间。
// 服务端时间统一为 UTC：格式 "YYYY-MM-DD HH:MM:SS"（无时区标记）
// 或 RFC3339；无标记时按 UTC 解析（补 Z），再输出本地同形字符串。
// 排序/比较仍用原字符串（UTC 字典序一致），只改显示。
export function fmtLocal(s?: string | null): string {
  if (!s) return '—'
  const iso = s.includes('T') ? s : s.replace(' ', 'T')
  const d = new Date(/(Z|[+-]\d{2}:?\d{2})$/.test(iso) ? iso : iso + 'Z')
  if (isNaN(d.getTime())) return s
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}
