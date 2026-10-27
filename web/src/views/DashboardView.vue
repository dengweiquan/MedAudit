<template>
  <div class="card">
    <h2 style="font-size:22px; margin:6px 0">{{ conclusion }}</h2>
  </div>

  <div class="card">
    <h2>需要你处理</h2>
    <div v-if="!todoAlerts.length && !dueRows.length" class="empty">暂无待办</div>
    <div v-for="a in todoAlerts" :key="'al' + a.id" class="alert-row">
      <div class="inline-form" style="justify-content:space-between">
        <span>
          <span class="concl c-FAIL">{{ a.kind === 'drift' ? '权限新增' : '复检失败' }}</span>
          <b style="margin-left:6px">{{ assetName(a.asset_id) }}</b>
        </span>
        <span class="row-actions">
          <button class="btn small" v-if="a.items?.length" @click="toggleAlert(a.id)">{{ openAlert === a.id ? '收起' : '看明细' }}</button>
          <button class="btn small primary" @click="ackAlert(a)">已知悉</button>
        </span>
      </div>
      <div class="todo" v-if="a.kind === 'drift'">与上次审计相比新增 {{ a.added_count }} 项授权/角色/账号，请确认是否为已批准的变更；不应存在的请回收，业务必需的请加入基线。</div>
      <div class="todo" v-else>原因：{{ a.error }}</div>
      <table v-if="openAlert === a.id && a.items?.length" style="margin-top:6px">
        <thead><tr><th>变化</th><th>账号</th><th>内容</th></tr></thead>
        <tbody>
          <tr v-for="(it, i) in a.items" :key="i"><td>{{ it.category }}</td><td>{{ it.subject }}</td><td>{{ it.detail }}</td></tr>
        </tbody>
      </table>
    </div>
    <table v-if="dueRows.length" style="margin-top:8px">
      <tbody>
        <tr v-for="d in dueRows" :key="d.asset_id">
          <td>{{ d.name }} <span v-if="d.auto" class="concl c-PASS">自动</span></td>
          <td>{{ d.last_audit_at ? fmtLocal(d.last_audit_at) : '从未审计' }}</td>
          <td>
            <span v-if="d.status === 'overdue'" class="concl c-FAIL">已逾期 {{ -d.days_left }} 天</span>
            <span v-else-if="d.status === 'never'" class="concl c-UNKNOWN">从未审计</span>
            <span v-else class="concl c-UNKNOWN">{{ d.days_left }} 天后到期</span>
          </td>
          <td><button class="btn small primary" @click="gotoObjects(kindCategory(d.kind))">去审计</button></td>
        </tr>
      </tbody>
    </table>
    <div class="todo" style="margin-top:8px">每个对象每 {{ cycleDays }} 天复检一次（7 天内到期即提醒）。标「自动」的对象到期由平台自动执行。</div>
  </div>

  <div class="card" v-if="topRisks.length">
    <h2>先改这些</h2>
    <table>
      <thead><tr><th>问题名称</th><th>对象</th><th>涉及账号数</th><th>操作</th></tr></thead>
      <tbody>
        <tr v-for="t in topRisks" :key="t.ruleId">
          <td>{{ t.name }}</td>
          <td>{{ t.objectText }}</td>
          <td>{{ t.accounts }} 个账号</td>
          <td><button class="btn small primary" @click="goto('findings', t.bundleId)">怎么改</button></td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>各类对象情况</h2>
    <div class="stat-grid">
      <div v-for="c in catCards" :key="c.key" class="stat clickable" :class="catAccent(c.key)" style="cursor:pointer" @click="gotoObjects(c.key)">
        <div class="num">{{ c.problem }}<span class="todo"> / {{ c.assets }} 个对象</span></div>
        <div class="lbl">
          {{ c.label }}：<b v-if="c.total" style="color:#b91c1c">高 {{ c.high }} · 中 {{ c.medium }} · 低 {{ c.low }}</b><span v-else-if="c.assets">暂无问题</span><span v-else>暂无对象</span>
          <div class="todo">最近审计 {{ c.lastAt || '—' }} →</div>
        </div>
      </div>
    </div>
  </div>

  <div class="card" v-if="showHospitalProgress">
    <h2>医院整改进度</h2>
    <table>
      <thead><tr><th>医院</th><th>对象</th><th>有问题对象</th><th>待整改</th><th>状态</th><th>最近审计</th></tr></thead>
      <tbody>
        <tr v-for="h in hospitalRows" :key="h.id">
          <td>{{ h.name }}</td>
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
  <div class="msg err" v-if="error">{{ error }}</div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, type AlertRow, type AuditDueRow, type Asset, type BundleSummary, type Finding, type Hospital, type Rule, type SiteInfo } from '../api'
import { kindCategory, type CategoryKey } from '../categories'
import { goto, gotoObjects, selectedHospital, filterByHospital } from '../store'
import { latestBundleOf, latestFail, loadSite, fmtLocal } from '../util'

const site = ref<SiteInfo | null>(null)

interface CatCard { key: CategoryKey; label: string; assets: number; problem: number; total: number; high: number; medium: number; low: number; lastAt: string }
interface HospRow { id: string; name: string; assets: number; problemAssets: number; fail: number; status: 'clear' | 'open' | 'none'; lastAt: string }
interface TopRisk { ruleId: string; name: string; objectText: string; accounts: number; bundleId: string }

const assets = ref<Asset[]>([])
const bundles = ref<BundleSummary[]>([])
const latestByAsset = ref(new Map<string, BundleSummary>())
const hospitals = ref<Hospital[]>([])
const rules = ref<Rule[]>([])
const error = ref('')
const failByAsset = ref<Map<string, number>>(new Map())
const failsByAsset = ref<Map<string, Finding[]>>(new Map())

const alertAll = ref<AlertRow[]>([])
const todoAlerts = computed(() => filterByHospital(alertAll.value))
const openAlert = ref(0)
function toggleAlert(id: number) { openAlert.value = openAlert.value === id ? 0 : id }
async function ackAlert(a: AlertRow) {
  try { await api.ackAlert(a.id); alertAll.value = alertAll.value.filter(x => x.id !== a.id) }
  catch (e) { error.value = e instanceof Error ? e.message : '确认失败' }
}

const dueAll = ref<AuditDueRow[]>([])
const cycleDays = ref(30)
const dueRows = computed(() => filterByHospital(dueAll.value).filter(d => d.status !== 'ok'))

const ruleById = computed(() => new Map(rules.value.map(r => [r.ID, r])))
const problemAssets = computed(() => [...failByAsset.value.values()].filter(f => f > 0).length)
const riskTotals = computed(() => {
  const t = { high: 0, medium: 0, low: 0 }
  for (const fails of failsByAsset.value.values()) {
    for (const f of fails) {
      const r = (ruleById.value.get(f.rule_id)?.Risk ?? '').toLowerCase()
      if (r === 'high') t.high++
      else if (r === 'medium') t.medium++
      else if (r === 'low') t.low++
    }
  }
  return t
})
const scopeLabel = computed(() => {
  if (selectedHospital.id) return hospitals.value.find(h => h.id === selectedHospital.id)?.name ?? '本院'
  if (site.value?.hospital_id) return '本院'
  return '全部医院'
})
const conclusion = computed(() => {
  if (!assets.value.length) return '暂无审计对象'
  if (problemAssets.value === 0) return '全部对象检查通过'
  return `${scopeLabel.value} ${assets.value.length} 个对象，${problemAssets.value} 个有问题；高风险 ${riskTotals.value.high} 项待整改。`
})

// 先改这些：高风险问题按类型（规则）取前 5 条。
const topRisks = computed<TopRisk[]>(() => {
  const byRule = new Map<string, { fails: number; subjects: Set<string>; objects: Map<string, string>; bundleId: string }>()
  for (const [assetId, fails] of failsByAsset.value) {
    for (const f of fails) {
      if ((ruleById.value.get(f.rule_id)?.Risk ?? '').toLowerCase() !== 'high') continue
      const g = byRule.get(f.rule_id) ?? { fails: 0, subjects: new Set<string>(), objects: new Map<string, string>(), bundleId: f.bundle_id }
      g.fails++
      g.subjects.add(f.subject)
      const an = assets.value.find(a => a.id === assetId)?.name ?? assetId
      g.objects.set(assetId, an)
      byRule.set(f.rule_id, g)
    }
  }
  return [...byRule.entries()]
    .sort((a, b) => b[1].fails - a[1].fails)
    .slice(0, 5)
    .map(([ruleId, g]) => {
      const names = [...g.objects.values()]
      const objectText = names.length > 1 ? `${names[0]} 等 ${names.length} 个对象` : (names[0] ?? '')
      return { ruleId, name: ruleById.value.get(ruleId)?.Name ?? ruleId, objectText, accounts: g.subjects.size, bundleId: g.bundleId }
    })
})

const catCards = computed<CatCard[]>(() => {
  const defs: { key: CategoryKey; label: string }[] = [
    { key: 'db', label: '数据库' },
    { key: 'os', label: '操作系统' },
    { key: 'mw', label: '中间件' },
    { key: 'api', label: '业务接口' },
  ]
  return defs.map(d => {
    const catAssets = assets.value.filter(a => kindCategory(a.kind) === d.key)
    let problem = 0, total = 0, high = 0, medium = 0, low = 0, lastAt = ''
    for (const a of catAssets) {
      const fails = failsByAsset.value.get(a.id) ?? []
      if (fails.length > 0) problem++
      for (const f of fails) {
        total++
        const r = (ruleById.value.get(f.rule_id)?.Risk ?? '').toLowerCase()
        if (r === 'high') high++
        else if (r === 'medium') medium++
        else if (r === 'low') low++
      }
      const lb = latestOfAsset(a.id)
      if (lb && lb.imported_at > lastAt) lastAt = lb.imported_at
    }
    return { key: d.key, label: d.label, assets: catAssets.length, problem, total, high, medium, low, lastAt }
  })
})

// 医院整改进度只在多医院时显示（单院部署隐藏）。
const showHospitalProgress = computed(() => !site.value?.hospital_id && hospitals.value.length > 1)
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

function catAccent(c: CategoryKey): string {
  return { db: 'a-blue', os: 'a-teal', mw: 'a-violet', api: 'a-amber' }[c]
}
function assetName(id: string): string {
  return assets.value.find(a => a.id === id)?.name ?? id
}
function latestOfAsset(assetId: string): BundleSummary | undefined {
  return latestByAsset.value.get(assetId) ?? latestBundleOf(bundles.value, assetId)
}

async function load() {
  try {
    site.value = await loadSite()
    const [bs, as, hs, ru] = await Promise.all([
      api.bundles(), api.assets(), api.hospitals(), api.rules(),
    ])
    bundles.value = filterByHospital(bs); assets.value = filterByHospital(as); hospitals.value = hs
    rules.value = ru
    try { latestByAsset.value = new Map(filterByHospital(await api.latestBundles()).map(b => [b.asset_id, b])) } catch { latestByAsset.value = new Map() }
    try { alertAll.value = await api.alerts() } catch { alertAll.value = [] }
    try { const due = await api.auditDue(); dueAll.value = due.items; cycleDays.value = due.cycle_days } catch { dueAll.value = [] }
    const byAsset = new Map<string, number>()
    const failsMap = new Map<string, Finding[]>()
    for (const a of assets.value) {
      const lb = latestOfAsset(a.id)
      if (!lb) { byAsset.set(a.id, 0); continue }
      let fails: Finding[] = []
      try { fails = latestFail(await api.findings(lb.id)) } catch { fails = [] }
      byAsset.set(a.id, fails.length)
      failsMap.set(a.id, fails)
    }
    failByAsset.value = byAsset
    failsByAsset.value = failsMap
  } catch (e) {
    error.value = e instanceof Error ? e.message : '加载失败'
  }
}

onMounted(load)
</script>
