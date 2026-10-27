import { api, type BundleSummary, type Finding, type SiteInfo } from './api'

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
export function comparePair(bundles: BundleSummary[], assetId: string): ComparePair | null {
  const list = bundles.filter(b => b.asset_id === assetId)
    .sort((a, b) => a.imported_at.localeCompare(b.imported_at) || a.id.localeCompare(b.id))
  if (list.length < 2) return null
  return { old: list[list.length - 2], new: list[list.length - 1] }
}

export function bundlesOfAsset(bundles: BundleSummary[], assetId: string): BundleSummary[] {
  return bundles.filter(b => b.asset_id === assetId)
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
