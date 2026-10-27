import { describe, expect, it } from 'vitest'
import { baselineLabel } from './labels'

// M37-fix2-3：医院模式基线下拉用中文可读名称，不出现英文适配器代码与 ID。
describe('baselineLabel', () => {
  it('按适配器前缀映射类别中文名，版本号加创建日期区分同适配器多条基线', () => {
    expect(baselineLabel('db-mysql', 1, '2026-10-19 08:42:26')).toBe('数据库 · 第 1 版 · 10-19')
    expect(baselineLabel('db-mysql', 1, '2026-10-21 09:39:21')).toBe('数据库 · 第 1 版 · 10-21')
    expect(baselineLabel('os-linux', 1, '2026-10-20 10:00:00')).toBe('操作系统 · 第 1 版 · 10-20')
    expect(baselineLabel('mw-tomcat', 3, '2026-10-22 12:00:00')).toBe('中间件 · 第 3 版 · 10-22')
    expect(baselineLabel('api', 1, '2026-10-22 12:00:00')).toBe('业务接口 · 第 1 版 · 10-22')
  })
  it('标签不含英文代码与 ID', () => {
    for (const label of [baselineLabel('db-mysql', 1, '2026-10-19 08:42:26'), baselineLabel('os-windows', 1, '2026-10-21 09:39:21')]) {
      expect(label).not.toContain('db-mysql')
      expect(label).not.toContain('os-windows')
      expect(label).not.toMatch(/bl-[a-z0-9-]+/)
    }
  })
  it('未知适配器回退为未分类；无日期时省略日期段', () => {
    expect(baselineLabel('xx-foo', 1, '2026-10-20 10:00:00')).toBe('未分类 · 第 1 版 · 10-20')
    expect(baselineLabel('db-mysql', 1)).toBe('数据库 · 第 1 版')
  })
})
