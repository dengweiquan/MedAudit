<template>
  <div class="stat-grid" style="margin-bottom:16px">
    <div class="stat a-blue"><div class="num">{{ assets.length }}</div><div class="lbl">审计对象</div></div>
    <div class="stat a-red"><div class="num">{{ problemAssets }}</div><div class="lbl">有问题对象</div></div>
    <div class="stat a-amber"><div class="num">{{ openFail }}</div><div class="lbl">待整改问题（FAIL）</div></div>
    <div class="stat a-violet"><div class="num">{{ reports?.length ?? '—' }}</div><div class="lbl">已生成报告</div></div>
    <div class="stat a-slate"><div class="num">{{ rulesCount ?? '—' }}</div><div class="lbl">启用规则</div></div>
  </div>

  <div class="card" v-if="alertRows.length">
    <h2>告警（{{ alertRows.length }}）</h2>
    <div v-for="a in alertRows" :key="a.id" class="alert-row">
      <div class="inline-form" style="justify-content:space-between">
        <span>
          <span class="concl c-FAIL">{{ a.kind === 'drift' ? '权限新增' : '复检失败' }}</span>
          <b style="margin-left:6px">{{ assetName(a.asset_id) }}</b>
          <span class="todo">（{{ a.asset_id }}） · {{ fmtLocal(a.created_at) }}</span>
        </span>
        <span class="row-actions">
          <button class="btn small" v-if="a.items?.length" @click="toggleAlert(a.id)">{{ openAlert === a.id ? '收起' : '看明细' }}</button>
          <button class="btn small primary" @click="ackAlert(a)">已知悉</button>
        </span>
      </div>
      <div class="todo" v-if="a.kind === 'drift'">与上次审计相比新增 {{ a.added_count }} 项授权/角色/账号，请确认是否为已批准的变更；不应存在的请回收，业务必需的请加入基线。</div>
      <div class="todo" v-else>原因：{{ a.error }}</div>
      <table v-if="openAlert === a.id && a.items?.length" style="margin-top:6px">
        <thead><tr><th>变化</th><th>主体</th><th>内容</th></tr></thead>
        <tbody>
          <tr v-for="(it, i) in a.items" :key="i"><td>{{ it.category }}</td><td>{{ it.subject }}</td><td>{{ it.detail }}</td></tr>
        </tbody>
      </table>
      <div class="todo" v-if="openAlert === a.id && a.added_count > (a.items?.length ?? 0)">仅显示前 {{ a.items?.length }} 项，完整对比见「审计记录」工程师详情的漂移对比。</div>
    </div>
  </div>

  <div class="card">
    <h2>该复检了（{{ dueRows.length }}）</h2>
    <table v-if="dueRows.length">
      <thead><tr><th>对象</th><th>上次审计</th><th>状态</th><th>操作</th></tr></thead>
      <tbody>
        <tr v-for="d in dueRows" :key="d.asset_id">
          <td>{{ d.name }} <span v-if="d.auto" class="concl c-PASS">自动</span><div class="todo">{{ d.asset_id }}</div></td>
          <td>{{ d.last_audit_at ? fmtLocal(d.last_audit_at) : '—' }}</td>
          <td>
            <span v-if="d.status === 'overdue'" class="concl c-FAIL">已逾期 {{ -d.days_left }} 天</span>
            <span v-else-if="d.status === 'never'" class="concl c-UNKNOWN">从未审计</span>
            <span v-else class="concl c-UNKNOWN">{{ d.days_left }} 天后到期</span>
          </td>
          <td><button class="btn small primary" @click="gotoAsset(viewOfKind(d.kind), d.asset_id)">去审计</button></td>
        </tr>
      </tbody>
    </table>
    <div v-else class="todo">全部对象都在复检周期内。</div>
    <div class="todo" style="margin-top:8px">每个对象每 {{ cycleDays }} 天复检一次（7 天内到期即提醒）。标「自动」的对象已开启定期自动复检（在「管理」页设置），到期由平台自动执行；其余对象由工程师点「开始审计」复检。</div>
  </div>

  <div class="card">
    <h2>哪类有问题</h2>
    <div class="stat-grid">
      <div v-for="c in catCards" :key="c.key" class="stat clickable" :class="catAccent(c.key)" style="cursor:pointer" @click="goto(c.view)">
        <div class="num">{{ c.problem }}<span class="todo"> / {{ c.assets }} 个对象</span></div>
        <div class="lbl">
          {{ c.label }}：<b v-if="c.fail" style="color:#b91c1c">待整改 {{ c.fail }} 项</b><span v-else-if="c.assets">暂无问题</span><span v-else>暂无对象</span>
          <div class="todo">最近审计 {{ c.lastAt || '—' }} →</div>
        </div>
      </div>
    </div>
    <div class="todo" style="margin-top:10px">闭环流程：在类别页对对象点「开始审计」→ 看问题与整改说明 → 导出报告发负责人 → 整改后再次审计 → 在「复检对比」确认问题消除，直到清零。</div>
  </div>

  <div class="card" v-if="hospitalRows.length">
    <h2>{{ site?.hospital_id ? '本院整改进度' : '医院整改进度' }}</h2>
    <table>
      <thead><tr><th>医院</th><th>对象</th><th>有问题对象</th><th>待整改 FAIL</th><th>状态</th><th>最近审计</th></tr></thead>
      <tbody>
        <tr v-for="h in hospitalRows" :key="h.id">
          <td>{{ h.id }}<div class="todo">{{ h.name }}</div></td>
          <td>{{ h.assets }}</td>
          <td>{{ h.problemAssets }}</td>
          <td><b v-if="h.fail" style="color:#b91c1c">{{ h.fail }}</b><span v-else>0</span></td>
          <td>
            <span v-if="h.status === 'clear'" class="concl c-PASS">已清零</span>
            <span v-else-if="h.status === 'open'" class="concl c-FAIL">整改中</span>
            <span v-else class="concl c-UNKNOWN">未审计</span>
          </td>
          <td>{{ h.lastAt || '—' }}</td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>最近审计</h2>
    <div v-if="error" class="error">{{ error }}</div>
    <table v-else-if="recentRows.length">
      <thead><tr><th>对象</th><th>类别</th><th>事实包</th><th>FAIL</th><th>导入时间</th><th>操作</th></tr></thead>
      <tbody>
        <tr v-for="r in recentRows" :key="r.b.id">
          <td>{{ assetName(r.b.asset_id) }}<div class="todo">{{ r.b.asset_id }} · {{ r.b.hospital_id }}</div></td>
          <td>{{ catLabel(r.cat) }}</td>
          <td>{{ r.b.id }}</td>
          <td><span v-if="r.fail" class="concl c-FAIL">{{ r.fail }}</span><span v-else>0</span></td>
          <td>{{ fmtLocal(r.b.imported_at) }}</td>
          <td>
            <div class="row-actions">
              <button class="btn small" @click="goto('findings', r.b.id)">问题</button>
              <button class="btn small" :disabled="exporting === r.b.id" @click="doExport(r.b)">导出报告</button>
              <button class="btn small" v-if="bundleCountOf(r.b.asset_id) >= 2" @click="gotoAsset('recheck', r.b.asset_id)">复检对比</button>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty">暂无事实包。去类别页对对象开始审计，或到「管理」页登记新对象。</div>
    <div class="msg err" v-if="exportErr">{{ exportErr }}</div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, type AlertRow, type AuditDueRow, type Asset, type BundleSummary, type Hospital, type ReportRow, type SiteInfo } from '../api'
import { kindCategory, type CategoryKey } from '../categories'
import { goto, gotoAsset, selectedHospital, filterByHospital } from '../store'
import { bundleCategory, exportLatestReport, latestBundleOf, latestFail, loadSite, fmtLocal} from '../util'

const site = ref<SiteInfo | null>(null)

interface CatCard { key: string; view: string; label: string; assets: number; problem: number; fail: number; lastAt: string }
interface HospRow { id: string; name: string; assets: number; problemAssets: number; fail: number; status: 'clear' | 'open' | 'none'; lastAt: string }
interface RecentRow { b: BundleSummary; fail: number; cat: CategoryKey | 'unknown' }

const assets = ref<Asset[]>([])
const bundles = ref<BundleSummary[]>([])
const latestByAsset = ref(new Map<string, BundleSummary>())
const hospitals = ref<Hospital[]>([])
const reports = ref<ReportRow[] | null>(null)
const rulesCount = ref<number | null>(null)
const error = ref('')
const exporting = ref('')
const exportErr = ref('')
// 每资产最新包的最新轮 FAIL 数（assetId -> fail）
const failByAsset = ref<Map<string, number>>(new Map())
// 每包最新轮 FAIL 数（bundleId -> fail），仅最新包计算
const failByBundle = ref<Map<string, number>>(new Map())

const alertAll = ref<AlertRow[]>([])
const alertRows = computed(() => filterByHospital(alertAll.value))
const openAlert = ref(0)
function toggleAlert(id: number) { openAlert.value = openAlert.value === id ? 0 : id }
async function ackAlert(a: AlertRow) {
  try { await api.ackAlert(a.id); alertAll.value = alertAll.value.filter(x => x.id !== a.id) }
  catch (e) { error.value = e instanceof Error ? e.message : '确认失败' }
}

const dueAll = ref<AuditDueRow[]>([])
const cycleDays = ref(30)
const dueRows = computed(() => filterByHospital(dueAll.value).filter(d => d.status !== 'ok'))
function viewOfKind(kind: string): string {
  return { db: 'databases', os: 'os', mw: 'middleware', api: 'api' }[kindCategory(kind) as string] ?? 'admin'
}

const kindByAsset = computed(() => new Map(assets.value.map(a => [a.id, a.kind])))

const catCards = computed<CatCard[]>(() => {
  const defs: { key: CategoryKey; view: string; label: string }[] = [
    { key: 'db', view: 'databases', label: '数据库' },
    { key: 'os', view: 'os', label: '操作系统' },
    { key: 'mw', view: 'middleware', label: '中间件' },
    { key: 'api', view: 'api', label: '业务接口' },
  ]
  return defs.map(d => {
    const catAssets = assets.value.filter(a => kindCategory(a.kind) === d.key)
    let problem = 0, fail = 0, lastAt = ''
    for (const a of catAssets) {
      const f = failByAsset.value.get(a.id) ?? 0
      if (f > 0) { problem++; fail += f }
      const lb = latestOfAsset(a.id)
      if (lb && lb.imported_at > lastAt) lastAt = lb.imported_at
    }
    return { key: d.key, view: d.view, label: d.label, assets: catAssets.length, problem, fail, lastAt }
  })
})

const problemAssets = computed(() => [...failByAsset.value.values()].filter(f => f > 0).length)
const openFail = computed(() => [...failByAsset.value.values()].reduce((s, f) => s + f, 0))

const hospitalRows = computed<HospRow[]>(() => hospitals.value
  .filter(h => !selectedHospital.id || h.id === selectedHospital.id)
  .map(h => {
  const hs = assets.value.filter(a => a.hospital_id === h.id)
  let problem = 0, fail = 0, lastAt = '', audited = 0
  for (const a of hs) {
    const f = failByAsset.value.get(a.id) ?? 0
    if (f > 0) { problem++; fail += f }
    const lb = latestOfAsset(a.id)
    if (lb) { audited++; if (lb.imported_at > lastAt) lastAt = lb.imported_at }
  }
  return {
    id: h.id, name: h.name, assets: hs.length, problemAssets: problem, fail,
    status: audited === 0 ? 'none' : fail > 0 ? 'open' : 'clear', lastAt,
  }
}))

const recentRows = computed<RecentRow[]>(() =>
  [...bundles.value]
    .sort((x, y) => y.imported_at.localeCompare(x.imported_at))
    .slice(0, 6)
    .map(b => ({ b, fail: failByBundle.value.get(b.id) ?? 0, cat: bundleCategory(b, kindByAsset.value) })),
)

function catLabel(c: CategoryKey | 'unknown'): string {
  return { db: '数据库', os: '操作系统', mw: '中间件', api: '业务接口', unknown: '未分类' }[c]
}

function catAccent(c: CategoryKey): string {
  return { db: 'a-blue', os: 'a-teal', mw: 'a-violet', api: 'a-amber' }[c]
}
function assetName(id: string): string {
  return assets.value.find(a => a.id === id)?.name ?? id
}
function bundleCountOf(assetId: string): number {
  return bundles.value.filter(b => b.asset_id === assetId).length
}

async function doExport(b: BundleSummary) {
  exporting.value = b.id; exportErr.value = ''
  try { await exportLatestReport(b) }
  catch (e) { exportErr.value = e instanceof Error ? e.message : '导出失败' }
  finally { exporting.value = '' }
}

// 最新包优先用 /assets/latest-bundles，取不到时回退到列表内按时间取最大。
function latestOfAsset(assetId: string): BundleSummary | undefined {
  return latestByAsset.value.get(assetId) ?? latestBundleOf(bundles.value, assetId)
}

async function load() {
  try {
    site.value = await loadSite()
    const [bs, as, hs, rs, ru] = await Promise.all([
      api.bundles(), api.assets(), api.hospitals(), api.reports(), api.rules(),
    ])
    bundles.value = filterByHospital(bs); assets.value = filterByHospital(as); hospitals.value = hs; reports.value = filterByHospital(rs)
    // 每对象最新包单独取（M37-1.2）：bundles 列表只返回 100 条，老对象
    // 的最近审计不能用它算；取不到时各处回退到列表内按时间取最大。
    try { latestByAsset.value = new Map(filterByHospital(await api.latestBundles()).map(b => [b.asset_id, b])) } catch { latestByAsset.value = new Map() }
    // 启用规则 = 规则总数 − 本站已关闭数（M17 规则启停）
    let off = 0
    try { off = (await api.ruleToggles()).filter(t => !t.enabled).length } catch { off = 0 }
    rulesCount.value = ru.length - off
    try { alertAll.value = await api.alerts() } catch { alertAll.value = [] }
    try { const due = await api.auditDue(); dueAll.value = due.items; cycleDays.value = due.cycle_days } catch { dueAll.value = [] }
    const byAsset = new Map<string, number>()
    const byBundle = new Map<string, number>()
    // 顶部合计须与所选医院一致：用过滤后的资产算，勿用原始全院数组。
    for (const a of assets.value) {
      const lb = latestOfAsset(a.id)
      if (!lb) { byAsset.set(a.id, 0); continue }
      let fail = 0
      try { fail = latestFail(await api.findings(lb.id)).length } catch { fail = 0 }
      byAsset.set(a.id, fail)
      byBundle.set(lb.id, fail)
    }
    // 最近审计列表（前 6 个包）逐个补算 FAIL，避免非最新包显示误导性的 0。
    const recent = [...bs].sort((x, y) => y.imported_at.localeCompare(x.imported_at)).slice(0, 6)
    for (const b of recent) {
      if (byBundle.has(b.id)) continue
      try { byBundle.set(b.id, latestFail(await api.findings(b.id)).length) } catch { /* 保持缺省 */ }
    }
    failByAsset.value = byAsset
    failByBundle.value = byBundle
  } catch (e) {
    error.value = e instanceof Error ? e.message : '加载失败'
  }
}

onMounted(load)
</script>
