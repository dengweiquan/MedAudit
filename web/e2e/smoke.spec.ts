import { test, expect, type Page } from '@playwright/test'

// M37-2.9 医院模式冒烟（M37 方案阶段 2 验收）。
//
// 前置（按顺序）：
//   1. 起阶段 2 代码的服务（前端 dist 已构建），如：
//      ./medaudit-server -addr 127.0.0.1:18098 -web-dir web/dist
//   2. 加载演示数据（口令经环境变量传入，不写进文件）：
//      MEDAUDIT_USER=admin MEDAUDIT_PASS=<staging 口令> \
//        bash pilot/load-demo.sh http://127.0.0.1:18098
//   3. 跑本文件（环境变量见 ../playwright.config.ts）：
//      E2E_BASE_URL=http://127.0.0.1:18098 npm run test:e2e
//
// 断言（医院模式，默认 localStorage 为空即医院模式）：
//   - 顶栏菜单恰好 5 个：首页/审计对象/问题/报告/复检对比
//   - 首页有一句话结论
//   - 逐页可见文本不含英文代码与内部编号：bundle-、h-demo、db.mysql.、
//     资产 ID、FAIL/PASS、high/medium/low
//   - 复检对比：UI 句子里的修复/新增/还剩三数与服务端事实包按
//     (imported_at, id) 升序取最后两次重算的多重集差分一致——
//     若 UI 把上次/本次颠倒（M37-1.1 原 Bug），修复与新增会对调，
//     本断言即失败
// 截图存 e2e/__screens__/（不入库，供 PR 描述用）。
//
// 注意：本文件不依赖服务端以外的任何状态；演示数据须先加载。

const ADMIN_USER = process.env.E2E_ADMIN_USER || 'admin'
const ADMIN_PASS = process.env.E2E_ADMIN_PASSWORD || 'Stage@123456'
const DEMO_MYSQL = '演示 MySQL 8.0'

// 医院模式可见文本里不该出现的英文代码与内部编号。
const FORBIDDEN = [
  'bundle-',
  'h-demo',
  'db.mysql.',
  'db-mysql-demo',
  'db-pg-demo',
  'db-oracle-demo',
  'os-linux-demo',
  'mw-tomcat-demo',
  'FAIL',
  'PASS',
  'high',
  'medium',
  'low',
]

interface BundleSummary {
  id: string
  asset_id: string
  hospital_id: string
  imported_at: string
}

interface Finding {
  rule_id: string
  subject: string
  conclusion: string
  detail: string
  created_at: string
}

async function assertNoForbiddenText(page: Page) {
  const text = await page.locator('body').innerText()
  for (const token of FORBIDDEN) {
    expect(text, `页面可见文本不应含 ${token}`).not.toContain(token)
  }
}

async function shot(page: Page, name: string) {
  await page.screenshot({ path: `e2e/__screens__/${name}.png` })
}

// 与 web/src/util.ts 的 latestRunFindings 相同口径：按 120 秒间隙聚类取最后一簇。
function latestRun(rows: Finding[]): Finding[] {
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

function bucket(rows: Finding[]): Map<string, number> {
  const m = new Map<string, number>()
  for (const f of rows) {
    let detail = ''
    try {
      detail = (JSON.parse(f.detail) as { detail?: string }).detail ?? ''
    } catch {
      detail = ''
    }
    const k = `${f.rule_id}|${f.subject}|${detail}`
    m.set(k, (m.get(k) ?? 0) + 1)
  }
  return m
}

test('医院模式冒烟：菜单、术语与复检对比顺序', async ({ page }) => {
  // 登录（口令模式为默认）。
  await page.goto('/')
  await page.locator('.login-card input').first().fill(ADMIN_USER)
  await page.locator('.login-card input[type="password"]').fill(ADMIN_PASS)
  await page.getByRole('button', { name: '登录', exact: true }).click()
  await expect(page.locator('nav.tabs')).toBeVisible()

  // 医院模式菜单恰好 5 个。
  await expect(page.locator('nav.tabs button')).toHaveCount(5)
  for (const name of ['首页', '审计对象', '问题', '报告', '复检对比']) {
    await expect(page.getByRole('button', { name, exact: true })).toBeVisible()
  }

  // 首页：一句话结论 + 截图。工作台会为每资产取最新问题，请求在切页
  // 后仍继续跑、占连接池；先等空闲，后面页的请求才不排队。
  const conclusion = page.locator('h2').first()
  await expect(conclusion).toHaveText(/个对象，.*个有问题|全部对象检查通过|暂无审计对象/)
  await page.waitForLoadState('networkidle', { timeout: 60000 })
  await assertNoForbiddenText(page)
  await shot(page, 'dashboard')

  // 审计对象：四类筛选齐全 + 截图。
  await page.getByRole('button', { name: '审计对象', exact: true }).click()
  for (const chip of ['全部', '数据库', '操作系统', '中间件', '业务接口']) {
    await expect(page.locator('body')).toContainText(chip)
  }
  await assertNoForbiddenText(page)
  await shot(page, 'objects')

  // 问题：按演示 MySQL 对象看 + 截图。等网络空闲再断言：问题分组
  // 是异步算出来的，半途断言可能撞上未加载完的中间态。
  await page.getByRole('button', { name: '问题', exact: true }).click()
  // 先等目标页标题出现再操作：切页是异步渲染，直接断言会撞上旧页。
  await expect(page.getByRole('heading', { name: '问题列表' })).toBeVisible()
  await page.locator('select').first().selectOption({ label: DEMO_MYSQL })
  await expect(page.locator('body')).toContainText(DEMO_MYSQL)
  await page.waitForLoadState('networkidle')
  // 等分组真正出现再断言，避免空列表下断言空过。
  await expect(page.getByRole('button', { name: '怎么改' }).first()).toBeVisible()
  await assertNoForbiddenText(page)
  await shot(page, 'findings')

  // 报告：一张表 + 截图。先等对象名出现：报告/事实包/资产三份数据
  // 到齐表格才完整，半途断言会撞上内部编号回退的中间态。
  await page.getByRole('button', { name: '报告', exact: true }).click()
  // 先等目标页标题出现再断言：表格与对象名在旧页（问题页）也存在，
  // 不等标题会直接在旧页上断言。
  await expect(page.getByRole('heading', { name: '生成报告' })).toBeVisible()
  await expect(page.locator('table').first()).toBeVisible()
  await expect(page.locator('body')).toContainText('演示 MySQL 8.0')
  await assertNoForbiddenText(page)
  await shot(page, 'reports')

  // 复检对比：选演示 MySQL，等句子出现，再用服务端数据重算三数核对。
  // 句子在新旧包确定后就出现，但三数要等两包的问题取回才算出；
  // 必须等网络空闲后再读数，否则会读到 0/0/0 的中间态。
  await page.getByRole('button', { name: '复检对比', exact: true }).click()
  await expect(page.getByRole('heading', { name: '复检对比' })).toBeVisible()
  await page.locator('select').first().selectOption({ label: DEMO_MYSQL })
  const sentence = page.getByText(
    /上次 \d\d-\d\d → 本次 \d\d-\d\d：修复 \d+ 项，新增 \d+ 项，还剩 \d+ 项。/,
  )
  await expect(sentence).toBeVisible()
  await page.waitForLoadState('networkidle')
  // 等新增小节出现才算对比真正算完（演示数据新增 6 项）；只等句子
  // 会读到对比中的 0/0/0 中间态，networkidle 又会被排队请求骗过。
  await expect(page.locator('h3', { hasText: '新增' })).toBeVisible({ timeout: 60000 })
  await assertNoForbiddenText(page)
  await shot(page, 'recheck')

  const m = (await sentence.innerText()).match(/修复 (\d+) 项，新增 (\d+) 项，还剩 (\d+) 项/)
  expect(m, '复检句子应含修复/新增/还剩三数').not.toBeNull()
  const [, uiFixed, uiAdded, uiRest] = m!.map(Number)

  const bundlesRes = await page.request.get('/api/v1/bundles')
  expect(bundlesRes.ok()).toBeTruthy()
  const bundles = (await bundlesRes.json()) as BundleSummary[]
  const mysqlBundles = bundles
    .filter((b) => b.asset_id === 'db-mysql-demo')
    .sort((a, b) => a.imported_at.localeCompare(b.imported_at) || a.id.localeCompare(b.id))
  expect(mysqlBundles.length).toBeGreaterThanOrEqual(2)
  const oldB = mysqlBundles[mysqlBundles.length - 2]
  const newB = mysqlBundles[mysqlBundles.length - 1]
  // 本次不早于上次（演示数据导入时逐包间隔 2 秒，正常应严格大于）。
  expect(newB.imported_at.localeCompare(oldB.imported_at)).toBeGreaterThanOrEqual(0)

  const [oldFindings, newFindings] = await Promise.all([
    page.request.get(`/api/v1/findings?bundle_id=${encodeURIComponent(oldB.id)}`).then((r) => r.json() as Promise<Finding[]>),
    page.request.get(`/api/v1/findings?bundle_id=${encodeURIComponent(newB.id)}`).then((r) => r.json() as Promise<Finding[]>),
  ])
  const oldBucket = bucket(latestRun(oldFindings).filter((f) => f.conclusion === 'FAIL'))
  const newBucket = bucket(latestRun(newFindings).filter((f) => f.conclusion === 'FAIL'))
  let fixed = 0
  let still = 0
  let added = 0
  for (const [k, n] of oldBucket) {
    const common = Math.min(n, newBucket.get(k) ?? 0)
    still += common
    fixed += n - common
  }
  for (const [k, n] of newBucket) {
    const common = Math.min(n, oldBucket.get(k) ?? 0)
    added += n - common
  }
  expect([uiFixed, uiAdded, uiRest]).toEqual([fixed, added, still + added])
})
