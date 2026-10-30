import { describe, expect, it } from 'vitest'
import type { BundleSummary } from './api'
import { buildConclusion, comparePair, countSnapshotRisks, latestBundleOf, loadBundlesByAssets, filterApiReports, hospitalProgressStatus } from './util'
import type { ApiAuditSummary } from './api'

// M37-1.1：服务端按 imported_at DESC 返回，直接取末尾会把新旧颠倒；
// 下面用例固定：无论输入顺序如何，本次一定是导入时间更晚的那个包。
function mk(id: string, imported_at: string): BundleSummary {
  return {
    id, plan_id: 'p', hospital_id: 'h', asset_id: 'a1', schema_version: '1',
    adapter: 'db-mysql', execution: 'COMPLETE', fact_count: 0, receipt_count: 0, imported_at,
  }
}

const OLD = '2026-10-20 10:00:00'
const NEW = '2026-10-27 09:00:00'

describe('comparePair', () => {
  it('服务端 DESC 顺序输入时，本次仍为时间更晚的包', () => {
    const pair = comparePair([mk('b-new', NEW), mk('b-old', OLD)], 'a1')
    expect(pair?.new.id).toBe('b-new')
    expect(pair?.old.id).toBe('b-old')
    expect(pair!.new.imported_at > pair!.old.imported_at).toBe(true)
  })

  it('升序输入时结果一致', () => {
    const pair = comparePair([mk('b-old', OLD), mk('b-new', NEW)], 'a1')
    expect(pair?.new.id).toBe('b-new')
    expect(pair?.old.id).toBe('b-old')
  })

  it('取最后两次，忽略更早的包', () => {
    const pair = comparePair(
      [mk('b-new', NEW), mk('b-mid', '2026-10-25 09:00:00'), mk('b-old', OLD)], 'a1')
    expect(pair?.new.id).toBe('b-new')
    expect(pair?.old.id).toBe('b-mid')
  })

  it('不足两次返回 null；只取同一对象的包', () => {
    expect(comparePair([mk('b-new', NEW)], 'a1')).toBeNull()
    const other = { ...mk('b-other', '2026-10-28 09:00:00'), asset_id: 'a2' }
    expect(comparePair([mk('b-old', OLD), mk('b-new', NEW), other], 'a1')?.new.id).toBe('b-new')
  })
})

describe('latestBundleOf', () => {
  it('不依赖输入顺序，取导入时间最晚的包', () => {
    const list = [mk('b-old', OLD), mk('b-new', NEW), mk('b-mid', '2026-10-25 09:00:00')]
    expect(latestBundleOf(list, 'a1')?.id).toBe('b-new')
    expect(latestBundleOf([...list].reverse(), 'a1')?.id).toBe('b-new')
  })

  it('无匹配对象返回 undefined', () => {
    expect(latestBundleOf([mk('b-old', OLD)], 'a9')).toBeUndefined()
  })
})

describe('comparePair 120 包场景（M37-fix-3）', () => {
  it('120 包仍取该对象最后两次，不受全局 100 条上限影响', () => {
    const many: BundleSummary[] = []
    for (let i = 0; i < 120; i++) {
      const d = new Date(Date.UTC(2026, 0, 1) + i * 86400000)
      many.push(mk(`a1-${String(i).padStart(3, '0')}`, d.toISOString().slice(0, 10) + ' 10:00:00'))
    }
    many.push({ ...mk('a2-new', '2026-12-31 10:00:00'), asset_id: 'a2' })
    const pair = comparePair(many, 'a1')
    expect(pair?.new.id).toBe('a1-119')
    expect(pair?.old.id).toBe('a1-118')
  })
})

describe('buildConclusion（M37-fix-4）', () => {
  it('未审计对象计入结论，不说全部通过', () => {
    expect(buildConclusion('本院', 5, 1, 3, 38)).toBe('本院 5 个对象，1 个未审计，3 个有问题；高风险 38 项待整改。')
  })
  it('全部未审计时不说通过', () => {
    expect(buildConclusion('本院', 5, 5, 0, 0)).toBe('本院 5 个对象，5 个未审计。')
  })
  it('全部审计过且无问题时才说全部通过', () => {
    expect(buildConclusion('本院', 5, 0, 0, 0)).toBe('全部对象检查通过')
  })
  it('无对象与只有问题时口径不变', () => {
    expect(buildConclusion('本院', 0, 0, 0, 0)).toBe('暂无审计对象')
    expect(buildConclusion('本院', 5, 0, 3, 38)).toBe('本院 5 个对象，3 个有问题；高风险 38 项待整改。')
  })
})

describe('countSnapshotRisks（M37-fix-5）', () => {
  const riskOf = (id: string) => ({ r1: 'high', r2: 'medium', r3: 'low' }[id] ?? '')
  // 单轮时间戳：旧用例隐含「快照只有一轮」，此处显式打上同一时间戳。
  const f = (rule_id: string, conclusion: string, created_at = '2026-10-20 10:00:00') => ({ rule_id, conclusion, created_at }) as never
  it('只计快照中不通过项，按规则风险分级；非不通过与未知规则归入未分级', () => {
    const c = countSnapshotRisks(
      [f('r1', 'FAIL'), f('r1', 'FAIL'), f('r2', 'FAIL'), f('r3', 'PASS'), f('rX', 'FAIL'), f('r2', 'UNKNOWN')],
      riskOf,
    )
    expect(c).toEqual({ high: 2, medium: 1, low: 0, other: 1 })
  })
  it('空快照全为 0', () => {
    expect(countSnapshotRisks([], riskOf)).toEqual({ high: 0, medium: 0, low: 0, other: 0 })
  })
})

describe('countSnapshotRisks 最新一轮（M37-fix2-1）', () => {
  const riskOf = (id: string) => ({ r1: 'high', r2: 'medium', r3: 'low' }[id] ?? '')
  const f = (rule_id: string, conclusion: string, created_at: string) => ({ rule_id, conclusion, created_at }) as never
  it('快照含两轮评估结果时只计最新一轮（旧轮翻倍的回归）', () => {
    const rows = [
      f('r1', 'FAIL', '2026-10-20 10:00:00'), f('r1', 'FAIL', '2026-10-20 10:00:01'), f('r2', 'FAIL', '2026-10-20 10:00:02'),
      f('r1', 'FAIL', '2026-10-20 11:00:00'), f('r3', 'FAIL', '2026-10-20 11:00:03'), f('r2', 'PASS', '2026-10-20 11:00:05'),
    ]
    // 旧口径会算成高 3 · 中 1 · 低 1；正确值只计最新一轮：高 1 · 低 1。
    expect(countSnapshotRisks(rows, riskOf)).toEqual({ high: 1, medium: 0, low: 1, other: 0 })
  })
  it('输入顺序打乱时仍只计最新一轮', () => {
    const rows = [
      f('r1', 'FAIL', '2026-10-20 11:00:00'),
      f('r1', 'FAIL', '2026-10-20 10:00:00'), f('r1', 'FAIL', '2026-10-20 10:00:01'),
    ]
    expect(countSnapshotRisks(rows, riskOf)).toEqual({ high: 1, medium: 0, low: 0, other: 0 })
  })
  it('一轮内多秒写入仍算同一轮', () => {
    const rows = [
      f('r1', 'FAIL', '2026-10-20 11:00:00'), f('r2', 'FAIL', '2026-10-20 11:00:30'), f('r3', 'FAIL', '2026-10-20 11:00:59'),
    ]
    expect(countSnapshotRisks(rows, riskOf)).toEqual({ high: 1, medium: 1, low: 1, other: 0 })
  })
})

describe('countSnapshotRisks 轮次号（M37-fix3）', () => {
  const riskOf = (id: string) => ({ r1: 'high', r2: 'medium', r3: 'low' }[id] ?? '')
  const f = (rule_id: string, conclusion: string, created_at: string, eval_run_id?: number) => ({ rule_id, conclusion, created_at, eval_run_id }) as never
  it('快速连评（间隔 <120 秒）按轮次号分轮，不并成一轮', () => {
    const rows = [
      f('r1', 'FAIL', '2026-10-20 10:00:00', 1), f('r2', 'FAIL', '2026-10-20 10:00:30', 1),
      f('r1', 'FAIL', '2026-10-20 10:01:00', 2),
    ]
    // 聚类口径会把三行并成一轮（高 2 · 中 1）；轮次号口径只计 run 2：高 1。
    expect(countSnapshotRisks(rows, riskOf)).toEqual({ high: 1, medium: 0, low: 0, other: 0 })
  })
  it('指定轮次号为空轮次时分级全 0，不回退上一轮', () => {
    const rows = [
      f('r1', 'FAIL', '2026-10-20 10:00:00', 1), f('r2', 'FAIL', '2026-10-20 10:00:30', 1),
    ]
    expect(countSnapshotRisks(rows, riskOf, 2)).toEqual({ high: 0, medium: 0, low: 0, other: 0 })
  })
  it('老快照无轮次号时回退聚类口径', () => {
    const rows = [
      f('r1', 'FAIL', '2026-10-20 10:00:00'), f('r1', 'FAIL', '2026-10-20 11:00:00'),
    ]
    expect(countSnapshotRisks(rows, riskOf)).toEqual({ high: 1, medium: 0, low: 0, other: 0 })
  })
})

describe('loadBundlesByAssets（M37-fix2-2）', () => {
  const b = (id: string, asset_id: string): BundleSummary => ({
    id, plan_id: 'p', hospital_id: 'h', asset_id, schema_version: '1',
    adapter: 'db-mysql', execution: 'COMPLETE', fact_count: 0, receipt_count: 0, imported_at: '2026-10-20 10:00:00',
  })
  it('一个对象取包失败时跳过该对象，其他对象仍可复检', async () => {
    const fetchFn = (assetId: string) => assetId === 'a-bad'
      ? Promise.reject(new Error('boom'))
      : Promise.resolve([b(`b-${assetId}`, assetId)])
    const out = await loadBundlesByAssets(['a1', 'a-bad', 'a2'], fetchFn)
    expect(out.map(x => x.id)).toEqual(['b-a1', 'b-a2'])
  })
  it('全部失败时返回空数组，不抛错', async () => {
    const out = await loadBundlesByAssets(['a-bad'], () => Promise.reject(new Error('boom')))
    expect(out).toEqual([])
  })
})

describe('filterApiReports（M37-fix2-4）', () => {
  const r = (target: string): ApiAuditSummary => ({
    report_id: `r-${target}`, target, execution: 'COMPLETE', total: 1,
    pass_count: 0, fail_count: 1, unknown_count: 0, not_run_count: 0, imported_at: '2026-10-20 10:00:00',
  })
  const byEndpoint = new Map([
    ['http://demo-api', { hospital_id: 'h-demo' }],
    ['http://other-api', { hospital_id: 'h-other' }],
  ])
  const rows = [r('http://demo-api'), r('http://other-api'), r('http://unmatched')]
  it('全部医院视图下全部显示', () => {
    expect(filterApiReports(rows, byEndpoint, '').map(x => x.target)).toEqual(
      ['http://demo-api', 'http://other-api', 'http://unmatched'])
  })
  it('选定医院时只留本院已匹配报告，他院已匹配与未匹配都不显示', () => {
    expect(filterApiReports(rows, byEndpoint, 'h-demo').map(x => x.target)).toEqual(['http://demo-api'])
  })
})

describe('hospitalProgressStatus（M37-fix2-5）', () => {
  it('全未审计', () => {
    expect(hospitalProgressStatus(5, 0, 0)).toEqual({ status: 'none', unaudited: 5 })
  })
  it('部分未审计且有问题：整改中优先，另有未审计数照常返回', () => {
    expect(hospitalProgressStatus(5, 3, 10)).toEqual({ status: 'open', unaudited: 2 })
  })
  it('部分未审计无问题：才显示部分未审计', () => {
    expect(hospitalProgressStatus(5, 3, 0)).toEqual({ status: 'partial', unaudited: 2 })
  })
  it('全部审计有问题：整改中，无未审计', () => {
    expect(hospitalProgressStatus(5, 5, 10)).toEqual({ status: 'open', unaudited: 0 })
  })
  it('全部审计无问题：已清零', () => {
    expect(hospitalProgressStatus(5, 5, 0)).toEqual({ status: 'clear', unaudited: 0 })
  })
})
