import { describe, expect, it } from 'vitest'
import type { BundleSummary } from './api'
import { comparePair, latestBundleOf } from './util'

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
