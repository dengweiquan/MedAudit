<template>
  <div class="card">
    <h2>审计对象</h2>
    <div class="row-actions" style="margin-bottom:10px">
      <button v-for="f in filters" :key="f.key" class="btn small" :class="{ primary: filter === f.key }" @click="filter = f.key">
        {{ f.label }}（{{ f.count }}）
      </button>
    </div>
    <div v-if="error" class="error">{{ error }}</div>
    <table v-else-if="shown.length">
      <thead><tr><th>对象名称</th><th>类别</th><th>上次审计</th><th>问题</th><th>操作</th></tr></thead>
      <tbody>
        <template v-for="a in shown" :key="a.id">
          <tr>
            <td>{{ a.name }}</td>
            <td>{{ categoryLabel(kindCategory(a.kind)) }}</td>
            <td>
              <template v-if="lastAt(a)">{{ lastAt(a) }}</template>
              <span v-else>未审计</span>
            </td>
            <td>{{ problemText(a) }}</td>
            <td>
              <div class="row-actions">
                <button class="btn small primary" :disabled="auditDisabled(a)" :title="auditDisabledReason(a) ?? undefined" @click="openAudit(a)">开始审计</button>
                <button class="btn small" :disabled="!hasQuestions(a)" @click="openQuestions(a)">看问题</button>
                <button class="btn small" :disabled="!canExport(a) || exporting === a.id" @click="doExport(a)">导出报告</button>
              </div>
              <div v-if="auditDisabled(a) && kindCategory(a.kind) === 'db'" class="todo">未配置连接，请工程师在管理页补全</div>
            </td>
          </tr>
          <tr v-if="guideAsset?.id === a.id">
            <td colspan="5">
              <p style="margin:4px 0">{{ guideText(a) }}</p>
              <pre>{{ commandFor(a) }}</pre>
              <p class="todo" style="margin:4px 0">采集完成后事实包自动回传本平台；也可在「审计记录」页手动上传，再在工程师详情里点「评估」。</p>
            </td>
          </tr>
          <tr v-if="apiDetailAsset?.id === a.id">
            <td colspan="5">
              <div v-if="apiDetailLoading" class="todo">加载中…</div>
              <table v-else-if="apiDetail?.checks?.length" style="margin-top:6px">
                <thead><tr><th>检查项</th><th>结论</th><th>说明</th></tr></thead>
                <tbody>
                  <tr v-for="c in apiDetail.checks" :key="c.probe">
                    <td>{{ c.probe }}</td>
                    <td><span class="concl" :class="'c-' + c.conclusion">{{ conclLabel(c.conclusion) }}</span></td>
                    <td style="font-size:13px">{{ c.detail }}</td>
                  </tr>
                </tbody>
              </table>
              <div v-else class="empty">该报告无逐项数据。</div>
            </td>
          </tr>
        </template>
      </tbody>
    </table>
    <div v-else class="empty">暂无此类对象。请工程师在「管理」页登记。</div>
    <div class="msg err" v-if="exportErr">{{ exportErr }}</div>
  </div>

  <div class="card" v-if="auditAsset">
    <h2>一键审计：{{ auditAsset.name }}</h2>
    <p class="todo">
      将以只读账号 {{ connOf(auditAsset)?.user }} 连接 {{ connOf(auditAsset)?.host }}:{{ connOf(auditAsset)?.port }}
      真实采集权限事实，随后自动评估并生成报告。口令仅本次使用，不保存。
    </p>
    <div class="inline-form">
      <input v-model="auditForm.password" type="password" placeholder="数据库口令" autocomplete="off" style="min-width:220px" />
      <label>基线
        <select v-model="auditForm.baseline_id">
          <option value="">无基线</option>
          <option v-for="b in baselinesOf(auditAsset.hospital_id)" :key="b.id" :value="b.id">{{ engineerMode.on ? b.id : (b.target || '基线') }}</option>
        </select>
      </label>
      <input v-model="auditForm.created_by" placeholder="审计人" />
      <button class="btn primary" :disabled="running || !auditForm.password" @click="runAudit">开始审计</button>
      <button class="btn" :disabled="running" @click="auditAsset = null">关闭</button>
    </div>
    <div v-if="running" class="todo">审计中…正在真实采集（大库可能需要数分钟），请勿关闭页面。</div>
    <div class="msg err" v-if="auditErr">{{ auditErr }}</div>
    <div v-if="result">
      <p>
        审计完成：采集事实 {{ result.facts }} 条 / 收据 {{ result.receipts }} 张；
        评估 {{ result.evaluation.total }} 条结果，不通过 {{ result.evaluation.fail }}，问题落库 {{ result.evaluation.findings_stored }}。
      </p>
      <div class="row-actions">
        <a class="btn primary" :href="api.reportDocxUrl(result.report_id)" download>下载 Word 审计报告</a>
        <button class="btn" @click="goto('findings', result.bundle_id)">查看问题</button>
        <button class="btn" @click="goto('reports')">报告详情</button>
      </div>
    </div>
  </div>

  <RemoteAuditCard :asset="remoteAsset" @close="remoteAsset = null" @done="load" />
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { api, parseRemote, type ApiAuditCheck, type ApiAuditSummary, type Asset, type AuditRunResult, type BaselineRow, type BundleSummary, type ConnConfig } from '../api'
import RemoteAuditCard from '../components/RemoteAuditCard.vue'
import { kindCategory, type CategoryKey } from '../categories'
import { nav, goto, filterByHospital, reviewerName, selectedHospital, engineerMode } from '../store'
import { exportLatestReport, latestBundleOf, latestFail, fmtLocal } from '../util'
import { conclLabel, categoryLabel, riskLabel } from '../labels'

const MW_PRODUCTS = [
  { kind: 'mw-tomcat', label: 'Tomcat', supported: true, type: 'tomcat' },
  { kind: 'mw-nginx', label: 'Nginx', supported: true, type: 'nginx' },
  { kind: 'mw-weblogic', label: 'WebLogic', supported: true, type: 'weblogic' },
  { kind: 'mw-iis', label: 'IIS', supported: true, type: 'iis' },
  { kind: 'mw-other', label: '其他中间件', supported: false, type: '' },
]
const OLD_KEY_FILTER: Record<string, CategoryKey> = { databases: 'db', os: 'os', middleware: 'mw', api: 'api' }

const assets = ref<Asset[]>([])
const bundles = ref<BundleSummary[]>([])
const latestByAsset = ref(new Map<string, BundleSummary>())
const riskMap = ref<Map<string, { high: number; medium: number; low: number; other: number }>>(new Map())
const apiAudits = ref<ApiAuditSummary[]>([])
const apiByAsset = ref(new Map<string, ApiAuditSummary>())
const baselinesMap = ref<Record<string, BaselineRow[]>>({})
const error = ref('')
const exporting = ref('')
const exportErr = ref('')

const filter = ref<CategoryKey | 'all'>('all')
function initFilter() {
  filter.value = OLD_KEY_FILTER[nav.view] ?? (nav.objectsFilter as CategoryKey | 'all') ?? 'all'
}
watch(() => [nav.view, nav.objectsFilter], initFilter)

const filters = computed(() => {
  const count = (k: CategoryKey) => assets.value.filter(a => kindCategory(a.kind) === k).length
  return [
    { key: 'all' as const, label: '全部', count: assets.value.length },
    { key: 'db' as const, label: categoryLabel('db'), count: count('db') },
    { key: 'os' as const, label: categoryLabel('os'), count: count('os') },
    { key: 'mw' as const, label: categoryLabel('mw'), count: count('mw') },
    { key: 'api' as const, label: categoryLabel('api'), count: count('api') },
  ]
})
const shown = computed(() => filter.value === 'all'
  ? assets.value
  : assets.value.filter(a => kindCategory(a.kind) === filter.value))

function connOf(a: Asset): ConnConfig | null {
  if (!a.labels) return null
  try {
    const c = JSON.parse(a.labels) as ConnConfig
    return c.host && c.port && c.user ? c : null
  } catch { return null }
}
function mwSupported(kind: string): boolean {
  return MW_PRODUCTS.find(p => p.kind === kind)?.supported ?? false
}
function latestBundle(assetId: string): BundleSummary | undefined {
  return latestByAsset.value.get(assetId) ?? latestBundleOf(bundles.value, assetId)
}
function lastAt(a: Asset): string {
  const lb = latestBundle(a.id)
  if (lb) return fmtLocal(lb.imported_at)
  return apiByAsset.value.get(a.id)?.imported_at ? fmtLocal(apiByAsset.value.get(a.id)!.imported_at) : ''
}
function problemText(a: Asset): string {
  const r = riskMap.value.get(a.id)
  if (r) {
    const total = r.high + r.medium + r.low + r.other
    if (total === 0) return '通过'
    const counts = { high: r.high, medium: r.medium, low: r.low } as const
    const parts = (Object.keys(counts) as ('high' | 'medium' | 'low')[])
      .filter(k => counts[k] > 0)
      .map(k => `${riskLabel(k)} ${counts[k]}`)
    if (r.other > 0) parts.push(`未分级 ${r.other}`)
    return parts.join(' · ')
  }
  const ap = apiByAsset.value.get(a.id)
  if (ap) return ap.fail_count > 0 ? `不通过 ${ap.fail_count} 项` : '通过'
  return '—'
}
function hasQuestions(a: Asset): boolean {
  return !!latestBundle(a.id) || !!apiByAsset.value.get(a.id)
}
function canExport(a: Asset): boolean {
  return !!latestBundle(a.id) || !!apiByAsset.value.get(a.id)
}
function auditDisabled(a: Asset): boolean {
  const cat = kindCategory(a.kind)
  if (cat === 'db') return !connOf(a)
  if (cat === 'mw') return !mwSupported(a.kind)
  return false
}
function auditDisabledReason(a: Asset): string | null {
  const cat = kindCategory(a.kind)
  if (cat === 'db' && !connOf(a)) return '未配置连接，请工程师在管理页补全'
  if (cat === 'mw' && !mwSupported(a.kind)) return '该产品仅登记，暂不支持采集'
  return null
}

async function load() {
  try {
    assets.value = filterByHospital(await api.assets())
    bundles.value = filterByHospital(await api.bundles())
    try { latestByAsset.value = new Map(filterByHospital(await api.latestBundles()).map(b => [b.asset_id, b])) } catch { latestByAsset.value = new Map() }
    const rules = await api.rules()
    const riskOf = new Map(rules.map(r => [r.ID, (r.Risk ?? '').toLowerCase()]))
    const rm = new Map<string, { high: number; medium: number; low: number; other: number }>()
    for (const a of assets.value) {
      const lb = latestBundle(a.id)
      if (!lb) continue
      try {
        const fails = latestFail(await api.findings(lb.id))
        const c = { high: 0, medium: 0, low: 0, other: 0 }
        for (const f of fails) {
          const r = riskOf.get(f.rule_id)
          if (r === 'high') c.high++
          else if (r === 'medium') c.medium++
          else if (r === 'low') c.low++
          else c.other++
        }
        rm.set(a.id, c)
      } catch { /* 未评估包 */ }
    }
    riskMap.value = rm
    // 接口审计报告按目标地址匹配本院接口资产（报告本身无医院归属列）。
    try {
      const all = await api.apiAudits()
      const eps = new Map(assets.value.filter(a => kindCategory(a.kind) === 'api' && a.endpoint).map(a => [a.endpoint as string, a.id]))
      const byAsset = new Map<string, ApiAuditSummary>()
      for (const r of [...all].sort((x, y) => y.imported_at.localeCompare(x.imported_at))) {
        const aid = eps.get(r.target)
        if (aid && !byAsset.has(aid)) byAsset.set(aid, r)
      }
      apiAudits.value = all
      apiByAsset.value = byAsset
    } catch { apiAudits.value = []; apiByAsset.value = new Map() }
    const allHs = await api.hospitals()
    const hs = selectedHospital.id ? allHs.filter(h => h.id === selectedHospital.id) : allHs
    for (const h of hs) {
      if (!(h.id in baselinesMap.value)) {
        try { baselinesMap.value[h.id] = await api.baselines(h.id) } catch { baselinesMap.value[h.id] = [] }
      }
    }
  } catch (e) { error.value = e instanceof Error ? e.message : '加载失败' }
}

async function doExport(a: Asset) {
  exporting.value = a.id; exportErr.value = ''
  try {
    const lb = latestBundle(a.id)
    if (lb) await exportLatestReport(lb)
    else {
      const ap = apiByAsset.value.get(a.id)
      if (ap) window.open(api.apiAuditDocxUrl(ap.report_id), '_blank')
    }
  } catch (e) { exportErr.value = e instanceof Error ? e.message : '导出失败' }
  finally { exporting.value = '' }
}

// ---- 开始审计：按类别分流 ----
const auditAsset = ref<Asset | null>(null)
const guideAsset = ref<Asset | null>(null)
const remoteAsset = ref<Asset | null>(null)
const apiDetailAsset = ref<Asset | null>(null)
const apiDetail = ref<{ checks: ApiAuditCheck[] } | null>(null)
const apiDetailLoading = ref(false)
const auditForm = ref({ password: '', baseline_id: '', created_by: '' })
const running = ref(false)
const auditErr = ref('')
const result = ref<AuditRunResult | null>(null)

function closePanels() {
  auditAsset.value = null; guideAsset.value = null; remoteAsset.value = null
  apiDetailAsset.value = null; apiDetail.value = null
}
function openAudit(a: Asset) {
  const wasGuide = guideAsset.value?.id === a.id
  const wasAudit = auditAsset.value?.id === a.id
  closePanels()
  const cat = kindCategory(a.kind)
  if (cat === 'db') {
    if (!wasAudit) {
      auditAsset.value = a
      auditForm.value = { password: '', baseline_id: '', created_by: reviewerName() }
      auditErr.value = ''; result.value = null
    }
  } else if (cat === 'api') {
    if (!wasGuide) guideAsset.value = a
  } else if (parseRemote(a)) {
    remoteAsset.value = a
  } else if (!wasGuide) {
    guideAsset.value = a
  }
}
function guideText(a: Asset): string {
  const cat = kindCategory(a.kind)
  if (cat === 'api') return '在接口所在环境运行采集器（把规范文件换成实际的 OpenAPI/HAR 文件）：'
  if (cat === 'os') return '在目标主机上以 root（Linux）/ 管理员（Windows）运行：'
  return '在中间件所在主机上运行（Tomcat 需 CATALINA_HOME，Nginx 需配置目录，WebLogic 需域根目录，IIS 可空=系统默认配置路径）：'
}
function commandFor(a: Asset): string {
  const origin = window.location.origin
  const cat = kindCategory(a.kind)
  if (cat === 'api') {
    return `medaudit-collector apicheck -f api-spec.yml -u ${origin}`
  }
  if (cat === 'mw') {
    const p = MW_PRODUCTS.find(x => x.kind === a.kind)
    const home = a.endpoint && a.endpoint.startsWith('/') ? a.endpoint : '<安装目录>'
    return [
      `medaudit-collector mw --type ${p?.type ?? 'tomcat'} --home ${home} --out bundle-mw.zip --hospital ${a.hospital_id} --asset ${a.id} --plan plan-web-${a.id}`,
      `medaudit-collector bundle upload --file bundle-mw.zip --server ${origin}`,
    ].join('\n')
  }
  return [
    `medaudit-collector os --out bundle-os.zip --hospital ${a.hospital_id} --asset ${a.id} --plan plan-web-${a.id}`,
    `medaudit-collector bundle upload --file bundle-os.zip --server ${origin}`,
  ].join('\n')
}
function baselinesOf(hospitalId: string): BaselineRow[] {
  return baselinesMap.value[hospitalId] || []
}
async function runAudit() {
  if (!auditAsset.value) return
  running.value = true
  auditErr.value = ''
  result.value = null
  try {
    result.value = await api.runAudit({
      asset_id: auditAsset.value.id,
      password: auditForm.value.password,
      baseline_id: auditForm.value.baseline_id || undefined,
      created_by: auditForm.value.created_by || undefined,
    })
    auditForm.value.password = ''
    await load()
  } catch (e) {
    auditErr.value = e instanceof Error ? e.message : '审计失败'
  } finally {
    running.value = false
  }
}
async function openQuestions(a: Asset) {
  const lb = latestBundle(a.id)
  if (lb) { goto('findings', lb.id); return }
  const ap = apiByAsset.value.get(a.id)
  if (!ap) return
  if (apiDetailAsset.value?.id === a.id) { apiDetailAsset.value = null; apiDetail.value = null; return }
  apiDetailAsset.value = a; apiDetail.value = null; apiDetailLoading.value = true
  try { apiDetail.value = await api.getApiAudit(ap.report_id) } catch { apiDetail.value = { checks: [] } }
  finally { apiDetailLoading.value = false }
}

onMounted(() => { initFilter(); load() })
</script>
