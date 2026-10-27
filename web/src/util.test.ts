import { describe, expect, it } from 'vitest'
import type { BundleSummary } from './api'
import { buildConclusion, comparePair, latestBundleOf } from './util'

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
