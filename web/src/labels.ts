// 全站中文术语集中映射（M37-2.8）：结论、风险、类别、复核状态、执行结果。
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

export function executionLabel(e: string): string {
  return { COMPLETE: '完整', PARTIAL: '部分', FAILED: '失败' }[e] ?? e
}

// 基线下拉中文标签（M37-fix2-3）：医院模式不显示适配器英文代码与基线 ID，
// 用「类别中文名 · 第 N 版 · 创建月日」区分同一适配器的多条基线；工程师模式仍显示 ID（调用方处理）。
// 光版本号不够：实测 xmsfy 有两条 db-mysql 第 1 版（bl-test-1、bl-mysql80-admin），
// 放行项数也同为 17 项，只有创建日期能区分（10-19 与 10-21），故日期段必不可少。
export function baselineLabel(target: string, version: number, createdAt?: string): string {
  let c = 'unknown'
  if (target.startsWith('db-')) c = 'db'
  else if (target.startsWith('os-')) c = 'os'
  else if (target.startsWith('mw-')) c = 'mw'
  else if (target === 'api') c = 'api'
  let label = `${categoryLabel(c)} · 第 ${version} 版`
  if (createdAt) {
    const iso = createdAt.includes('T') ? createdAt : createdAt.replace(' ', 'T')
    const d = new Date(/(Z|[+-]\d{2}:?\d{2})$/.test(iso) ? iso : iso + 'Z')
    if (!isNaN(d.getTime())) {
      const p = (n: number) => String(n).padStart(2, '0')
      label += ` · ${p(d.getMonth() + 1)}-${p(d.getDate())}`
    }
  }
  return label
}
