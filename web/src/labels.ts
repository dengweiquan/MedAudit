// 全站中文术语集中映射（M37-2.8）：结论、风险、类别、复核状态。
// 各页改用这里的函数，勿再散落硬编码英文代码；类别与状态的英文值只出现在
// 代码逻辑比较里，不直接显示给用户。
export function conclLabel(c: string): string {
  return { FAIL: '不通过', PASS: '通过', UNKNOWN: '证据不足', NOT_RUN: '未执行', NOT_APPLICABLE: '不适用' }[c] ?? c
}

export function riskLabel(r?: string): string {
  return { high: '高', medium: '中', low: '低' }[(r ?? '').toLowerCase()] ?? '—'
}

export function reviewLabel(r: string): string {
  return { confirmed: '已确认', false_positive: '误报', exception: '例外' }[r] ?? '未复核'
}

export function categoryLabel(c: string): string {
  return { db: '数据库', os: '操作系统', mw: '中间件', api: '业务接口', unknown: '未分类' }[c] ?? c
}
