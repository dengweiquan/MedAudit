<template>
  <div class="card">
    <h2>复检对比</h2>
    <p class="todo">整改后再次审计，对比最近两次：哪些已修复、哪些仍存在、哪些是新增。</p>
    <div class="inline-form">
      <label>对象
        <select v-model="assetId" @change="compare">
          <option v-for="a in candidates" :key="a.id" :value="a.id">{{ engineerMode.on ? a.name + '（' + a.id + ' · ' + bundleCount(a.id) + ' 个事实包）' : a.name }}</option>
        </select>
      </label>
      <span class="todo" v-if="asset && engineerMode.on">{{ asset.hospital_id }}</span>
    </div>
    <div v-if="error" class="error">{{ error }}</div>
    <div v-else-if="!loaded" class="empty">加载中…</div>
    <div v-else-if="!candidates.length" class="empty">暂无拥有两个以上事实包的对象。先对同一对象审计两次（整改前后各一次），再来这里看复检结果。</div>

    <div v-else-if="comparing" class="empty">对比中…</div>
    <template v-if="oldBundle && newBundle && !comparing">
      <p><b>{{ summaryLine }}</b></p>
      <p v-if="!still.length && !added.length" class="msg">本对象问题已全部清零。</p>

      <h3 v-if="fixed.length">已修复（{{ countOf(fixed) }}）</h3>
      <table v-if="fixed.length">
        <thead><tr><th>问题名称</th><th>账号</th><th>原问题</th><th>数量</th></tr></thead>
        <tbody><tr v-for="g in fixed" :key="'x' + g.f.id"><td :title="engineerMode.on ? g.f.rule_id : undefined">{{ ruleName(g.f.rule_id) }}</td><td>{{ g.f.subject }}</td><td>{{ text(g.f) }}</td><td>{{ g.n }}</td></tr></tbody>
      </table>

      <h3 v-if="still.length">
        <button class="btn small" @click="stillOpen = !stillOpen">{{ stillOpen ? '收起' : '展开' }}仍存在（{{ countOf(still) }}）</button>
      </h3>
      <table v-if="still.length && stillOpen">
        <thead><tr><th>问题名称</th><th>账号</th><th>问题</th><th>数量</th></tr></thead>
        <tbody><tr v-for="g in still" :key="'s' + g.f.id"><td :title="engineerMode.on ? g.f.rule_id : undefined">{{ ruleName(g.f.rule_id) }}</td><td>{{ g.f.subject }}</td><td>{{ text(g.f) }}</td><td>{{ g.n }}</td></tr></tbody>
      </table>

      <h3 v-if="added.length">新增（{{ countOf(added) }}）</h3>
      <table v-if="added.length">
        <thead><tr><th>问题名称</th><th>账号</th><th>问题</th><th>数量</th></tr></thead>
        <tbody><tr v-for="g in added" :key="'a' + g.f.id"><td :title="engineerMode.on ? g.f.rule_id : undefined">{{ ruleName(g.f.rule_id) }}</td><td>{{ g.f.subject }}</td><td>{{ text(g.f) }}</td><td>{{ g.n }}</td></tr></tbody>
      </table>

      <div class="row-actions" style="margin-top:12px">
        <button class="btn" @click="goto('findings', newBundle?.id)">查看本次问题</button>
        <button class="btn primary" :disabled="exporting" @click="doExport">导出本次报告</button>
      </div>
      <div class="msg err" v-if="exportErr">{{ exportErr }}</div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, type Asset, type BundleSummary, type Finding, type Rule } from '../api'
import { goto, nav, filterByHospital, engineerMode } from '../store'
import { bundlesOfAsset, comparePair, exportLatestReport, latestFailOf, fmtLocal, loadBundlesByAssets } from '../util'

const assets = ref<Asset[]>([])
const bundles = ref<BundleSummary[]>([])
const assetId = ref('')
const error = ref('')
const loaded = ref(false)
const exporting = ref(false)
const exportErr = ref('')
const oldBundle = ref<BundleSummary | null>(null)
const newBundle = ref<BundleSummary | null>(null)
interface Group { f: Finding; n: number }
const rulesMap = ref<Map<string, Rule>>(new Map())
const stillOpen = ref(false)
const comparing = ref(false)
let compareSeq = 0
const fixed = ref<Group[]>([])
const still = ref<Group[]>([])
const added = ref<Group[]>([])
function countOf(gs: Group[]): number { return gs.reduce((s, g) => s + g.n, 0) }

function ruleName(id: string): string {
  return rulesMap.value.get(id)?.Name ?? id
}
function shortDate(ts: string): string {
  // 与 fmtLocal 同一本地化口径：先转本地时间再取月日，避免 UTC 日期与本地日期差一天。
  return fmtLocal(ts).slice(5, 10)
}
const summaryLine = computed(() => {
  if (!oldBundle.value || !newBundle.value) return ''
  const rest = countOf(still.value) + countOf(added.value)
  return `上次 ${shortDate(oldBundle.value.imported_at)} → 本次 ${shortDate(newBundle.value.imported_at)}：修复 ${countOf(fixed.value)} 项，新增 ${countOf(added.value)} 项，还剩 ${rest} 项。`
})

const candidates = computed(() => assets.value.filter(a => bundleCount(a.id) >= 2))
const asset = computed(() => assets.value.find(a => a.id === assetId.value))

function bundleCount(id: string): number {
  return bundles.value.filter(b => b.asset_id === id).length
}
// 问题身份 = 规则 + 主体 + 问题文本：同主体同规则可有多条不同问题
// （如每个全局权限一条），文本来自事实属性、跨包稳定；证据事实 ID 跨包不可比。
// 同键仍可多重（同权限多来源），按多重集计数对比。
function key(f: Finding): string { return f.rule_id + '|' + f.subject + '|' + text(f) }
function bucket(rows: Finding[]): Map<string, Group> {
  const m = new Map<string, Group>()
  for (const f of rows) {
    const k = key(f)
    const g = m.get(k)
    if (g) g.n++
    else m.set(k, { f, n: 1 })
  }
  return m
}
function text(f: Finding): string {
  try {
    const d = JSON.parse(f.detail) as { detail?: string }
    return d.detail ?? ''
  } catch { return '' }
}

async function compare() {
  error.value = ''
  const seq = ++compareSeq
  fixed.value = []; still.value = []; added.value = []
  oldBundle.value = null; newBundle.value = null
  if (!assetId.value) return
  // 服务端按 imported_at DESC 返回，直接取末尾会把新旧颠倒（M37-1.1），
  // 故用 comparePair 显式按时间升序取最后两次。
  const pair = comparePair(bundles.value, assetId.value)
  if (!pair) return
  const nb = pair.new
  const ob = pair.old
  newBundle.value = nb; oldBundle.value = ob
  comparing.value = true
  try {
    const [of, nf] = await Promise.all([latestFailOf(ob.id), latestFailOf(nb.id)])
    if (seq !== compareSeq) return
    const oldB = bucket(of)
    const newB = bucket(nf)
    for (const [k, og] of oldB) {
      const ng = newB.get(k)
      const common = Math.min(og.n, ng?.n ?? 0)
      if (common > 0) still.value.push({ f: ng!.f, n: common })
      if (og.n > common) fixed.value.push({ f: og.f, n: og.n - common })
    }
    for (const [k, ng] of newB) {
      const og = oldB.get(k)
      const common = Math.min(ng.n, og?.n ?? 0)
      if (ng.n > common) added.value.push({ f: ng.f, n: ng.n - common })
    }
    comparing.value = false
  } catch (e) {
    if (seq !== compareSeq) return
    comparing.value = false
    error.value = e instanceof Error ? e.message : '对比失败'
  }
}

async function doExport() {
  if (!newBundle.value) return
  exporting.value = true; exportErr.value = ''
  try { await exportLatestReport(newBundle.value) }
  catch (e) { exportErr.value = e instanceof Error ? e.message : '导出失败' }
  finally { exporting.value = false }
}

onMounted(async () => {
  try {
    assets.value = filterByHospital(await api.assets())
    // 候选对象需每对象包数量：改按对象逐个取全部包再合并，不再用全局 100 条列表（M37-fix-3）。
    try {
      const latest = filterByHospital(await api.latestBundles())
      bundles.value = await loadBundlesByAssets(latest.map(b => b.asset_id), id => api.assetBundles(id))
    } catch { bundles.value = [] }
    try {
      const rs = await api.rules()
      rulesMap.value = new Map(rs.map(r => [r.ID, r]))
    } catch { /* 无规则说明时降级显示规则 ID */ }
    const wanted = nav.assetId
    // 用户已在加载期间选过对象时不覆盖、不重算，否则后到的 mount 对比会覆盖用户所选对象的结论。
    if (!assetId.value) {
      assetId.value = (wanted && candidates.value.some(a => a.id === wanted)) ? wanted : (candidates.value[0]?.id ?? '')
      await compare()
    }
  } catch (e) { error.value = e instanceof Error ? e.message : '加载失败' } finally { loaded.value = true }
})
</script>
