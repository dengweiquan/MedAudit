<template>
  <div class="card">
    <h2>生成报告</h2>
    <div class="inline-form">
      <label>对象
        <select v-model="genAsset" @change="loadGenBundles">
          <option v-for="a in reportableAssets" :key="a.id" :value="a.id">{{ a.name }}</option>
        </select>
      </label>
      <label>审计记录
        <select v-model="genBundle">
          <option v-for="b in bundlesOfAsset(genAsset)" :key="b.id" :value="b.id">{{ engineerMode.on ? fmtLocal(b.imported_at) + '（' + b.id + '）' : fmtLocal(b.imported_at) }}</option>
        </select>
      </label>
      <button class="btn primary" :disabled="!genBundle" @click="generate">生成报告</button>
      <span class="msg" v-if="genMsg">{{ genMsg }}</span>
      <span class="msg err" v-if="genErr">{{ genErr }}</span>
    </div>
    <div class="todo">默认对对象的最近一次审计生成；生成人自动记为当前登录账号（{{ createdBy || '—' }}）。</div>
  </div>

  <div class="card">
    <h2>报告</h2>
    <div v-if="error" class="error">{{ error }}</div>
    <table v-else-if="loaded && reportGroups.length">
      <thead><tr><th>对象</th><th>生成时间</th><th>问题数</th><th>合规</th><th>操作</th></tr></thead>
      <tbody>
        <template v-for="g in reportGroups" :key="g.key">
          <tr :class="{ selected: detailId === g.reports[0].id }">
            <td>{{ g.name }}</td>
            <td>{{ fmtLocal(g.reports[0].created_at) }}</td>
            <td>{{ riskText(g.key) }}</td>
            <td>{{ complianceText(g.key) }}</td>
            <td>
              <div class="row-actions">
                <button class="btn small" @click="view(g.reports[0].id)">查看</button>
                <a class="btn small" :href="api.reportDocxUrl(g.reports[0].id)" download>下载 Word</a>
                <a class="btn small" :href="api.reportCsvUrl(g.reports[0].id)" download>CSV</a>
              </div>
            </td>
          </tr>
          <template v-if="historyOpen.has(g.key)">
            <tr v-for="r in g.reports.slice(1)" :key="r.id" :class="{ selected: detailId === r.id }">
              <td><span class="todo">历史</span></td>
              <td>{{ fmtLocal(r.created_at) }}</td>
              <td>{{ riskTextForReport(r) }}</td>
              <td>{{ complianceTextForReport(r) }}</td>
              <td>
                <div class="row-actions">
                  <button class="btn small" @click="view(r.id)">查看</button>
                  <a class="btn small" :href="api.reportDocxUrl(r.id)" download>下载 Word</a>
                  <a class="btn small" :href="api.reportCsvUrl(r.id)" download>CSV</a>
                </div>
              </td>
            </tr>
            <tr>
              <td colspan="5"><button class="btn small" @click="historyOpen.delete(g.key)">收起历史</button></td>
            </tr>
          </template>
          <tr v-else-if="g.reports.length > 1">
            <td colspan="5"><button class="btn small" @click="expandHistory(g)">显示历史报告（{{ g.reports.length - 1 }} 份）</button></td>
          </tr>
        </template>
      </tbody>
    </table>
    <div v-else-if="loaded" class="empty">暂无报告。</div>
    <div v-else class="empty">加载中…</div>
  </div>

  <div class="card">
    <h2>业务接口报告</h2>
    <table v-if="loaded && apiReportRows.length">
      <thead><tr><th>目标</th><th>时间</th><th>不通过数</th><th>操作</th></tr></thead>
      <tbody>
        <tr v-for="r in apiReportRows" :key="r.report_id">
          <td>{{ r.name }}</td>
          <td>{{ fmtLocal(r.imported_at) }}</td>
          <td>{{ r.fail_count > 0 ? `不通过 ${r.fail_count} 条` : '通过' }}</td>
          <td><a class="btn small" :href="api.apiAuditDocxUrl(r.report_id)" download>下载 Word</a></td>
        </tr>
      </tbody>
    </table>
    <div v-else-if="loaded" class="empty">暂无业务接口报告。</div>
    <div v-else class="empty">加载中…</div>
  </div>

  <div class="card" v-if="detail">
    <h2>报告详情<span v-if="engineerMode.on">（{{ detailId }}）</span></h2>
    <p>
      结论摘要：
      <span v-for="(n, c) in (detail.conclusion_summary as Record<string, number>) || {}" :key="c"
            class="concl" :class="'c-' + c" style="margin-right:4px">{{ conclLabel(c) }} {{ n }}</span>
    </p>
    <h3>覆盖（coverage）</h3>
    <pre>{{ JSON.stringify(detail.coverage ?? detail.coverage_note ?? '（旧报告无覆盖数据）', null, 2) }}</pre>
    <template v-if="pathsSection">
      <h3>跨层提权路径（关联分析）</h3>
      <p class="todo">
        提权路径共 {{ pathsSection.path_count }} 条{{ pathsSection.paths.length < pathsSection.path_count ? `，此处列 ${pathsSection.paths.length} 条` : '' }}。
      </p>
      <table v-if="pathsSection.paths.length">
        <thead><tr><th>风险</th><th>路径链</th></tr></thead>
        <tbody>
          <tr v-for="(p, i) in pathsSection.paths" :key="i">
            <td><span class="concl" :class="p.risk === 'high' ? 'c-FAIL' : 'c-UNKNOWN'">{{ riskLabel(p.risk) }}</span></td>
            <td>{{ p.chain }}</td>
          </tr>
        </tbody>
      </table>
      <div v-else class="empty">该关联报告未发现提权路径。</div>
    </template>
    <template v-if="driftSection">
      <h3>权限漂移（与上一次审计对比）</h3>
      <p class="todo">
        新增 {{ driftSection.added_total }} 项、消失 {{ driftSection.removed_total }} 项，
        其中 <b style="color:#b91c1c">新增授权/角色关系 {{ driftSection.attention }} 项</b>需重点关注。
      </p>
      <table v-if="driftSection.added.length || driftSection.removed.length">
        <thead><tr><th>方向</th><th>类别</th><th>账号</th><th>明细</th></tr></thead>
        <tbody>
          <tr v-for="(it, i) in driftSection.added" :key="'a' + i">
            <td><span class="concl c-FAIL">新增</span></td><td>{{ it.category }}</td><td>{{ it.subject }}</td><td>{{ it.detail }}</td>
          </tr>
          <tr v-for="(it, i) in driftSection.removed" :key="'r' + i">
            <td><span class="concl c-PASS">消失</span></td><td>{{ it.category }}</td><td>{{ it.subject }}</td><td>{{ it.detail }}</td>
          </tr>
        </tbody>
      </table>
    </template>
    <template v-if="remediationSection">
      <h3>修复与回滚脚本</h3>
      <p class="todo">
        不通过共 {{ remediationSection.fail_total }} 条，已生成脚本 {{ remediationSection.generated }} 条
        （快照存入 {{ remediationSection.stored }} 条）；未生成的为程序性整改项。脚本仅供人工评审后执行，平台不自动修改目标权限。
      </p>
      <div v-for="(s, i) in visibleScripts" :key="s.finding_id" class="fixscript">
        <details>
          <summary><b :title="engineerMode.on ? s.rule_id : undefined">{{ ruleName(s.rule_id) }}</b> · {{ s.subject }}<span v-if="s.scope"> · {{ s.scope }}</span></summary>
          <p class="fixlabel">前置检查</p><pre>{{ s.precheck }}</pre>
          <p class="fixlabel">修复命令 <button class="btn small" @click="copyText(s.fix)">复制</button></p><pre>{{ s.fix }}</pre>
          <p class="fixlabel">验证</p><pre>{{ s.verify }}</pre>
          <p class="fixlabel">回滚命令 <button class="btn small" @click="copyText(s.rollback)">复制</button></p><pre>{{ s.rollback }}</pre>
          <p v-if="s.note" class="todo">备注：{{ s.note }}</p>
        </details>
      </div>
      <button v-if="remediationSection.scripts.length > scriptShow" class="btn small" @click="scriptShow += 50">
        显示更多（剩余 {{ remediationSection.scripts.length - scriptShow }} 条）
      </button>
      <span class="msg" v-if="copyMsg">{{ copyMsg }}</span>
    </template>
    <h3>问题清单（{{ snapshotFindings.length }}）</h3>
    <table v-if="snapshotFindings.length">
      <thead><tr><th>规则</th><th>账号</th><th>结论</th><th>复核</th></tr></thead>
      <tbody>
        <tr v-for="f in snapshotFindings" :key="f.id">
          <td :title="engineerMode.on ? f.rule_id : undefined">{{ ruleName(f.rule_id) }}</td><td>{{ f.subject }}</td>
          <td><span class="concl" :class="'c-' + f.conclusion">{{ conclLabel(f.conclusion) }}</span></td>
          <td>{{ reviewLabel(f.review_status) }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { api, type ApiAuditSummary, type Asset, type BundleSummary, type Finding, type ReportDriftSection, type ReportPathsSection, type ReportRemediationSection, type ReportRow, type Rule } from '../api'
import { fmtLocal, latestBundleOf, latestFail } from '../util'
import { conclLabel, riskLabel, reviewLabel } from '../labels'
import { reviewerName, filterByHospital, engineerMode } from '../store'

const assets = ref<Asset[]>([])
const reports = ref<ReportRow[]>([])
const latestByAsset = ref(new Map<string, BundleSummary>())
const genBundles = ref<BundleSummary[]>([])
async function loadGenBundles() {
  if (!genAsset.value) { genBundles.value = []; genBundle.value = ''; return }
  try {
    genBundles.value = await api.assetBundles(genAsset.value)
    genBundle.value = latestBundleOf(genBundles.value, genAsset.value)?.id ?? ''
  } catch { genBundles.value = []; genBundle.value = '' }
}
const apiReports = ref<ApiAuditSummary[]>([])
const apiReportRows = computed(() => {
  const byEndpoint = new Map(assets.value.filter(a => a.endpoint).map(a => [a.endpoint as string, a.name]))
  return apiReports.value
    .map(r => ({ ...r, name: byEndpoint.get(r.target) ?? r.target }))
    .sort((x, y) => y.imported_at.localeCompare(x.imported_at))
})
const loaded = ref(false)
const rulesMap = ref<Map<string, Rule>>(new Map())
const genAsset = ref('')
const genBundle = ref('')
const createdBy = ref(reviewerName())
const historyOpen = reactive(new Set<string>())

const reportableAssets = computed(() => assets.value.filter(a => latestByAsset.value.has(a.id)))
function bundlesOfAsset(assetId: string): BundleSummary[] {
  return genBundles.value.filter(b => b.asset_id === assetId)
}
interface ReportGroup { key: string; name: string; reports: ReportRow[] }
const reportGroups = computed<ReportGroup[]>(() => {
  const byKey = new Map<string, ReportRow[]>()
  for (const r of reports.value) {
    const key = r.asset_id || r.bundle_id
    const list = byKey.get(key) ?? []
    list.push(r)
    byKey.set(key, list)
  }
  const out: ReportGroup[] = []
  for (const [key, list] of byKey) {
    const a = assets.value.find(x => x.id === key)
    out.push({
      key,
      name: a?.name ?? key,
      reports: [...list].sort((x, y) => y.created_at.localeCompare(x.created_at)),
    })
  }
  return out.sort((x, y) => (y.reports[0]?.created_at ?? '').localeCompare(x.reports[0]?.created_at ?? ''))
})
function ruleName(id: string): string {
  return rulesMap.value.get(id)?.Name ?? id
}
// 每份报告的问题数（高/中/低）与合规不满足条数：按报告的包取最新轮问题与报告详情合规段。
const riskByReport = ref<Map<string, { high: number; medium: number; low: number; other: number }>>(new Map())
const complianceFailByReport = ref<Map<string, number | null>>(new Map())
function riskTextForReport(r: ReportRow): string {
  const c = riskByReport.value.get(r.id)
  if (!c) return '—'
  const total = c.high + c.medium + c.low + c.other
  if (total === 0) return '通过'
  const parts = [`高 ${c.high}`, `中 ${c.medium}`, `低 ${c.low}`].filter((_, i) => [c.high, c.medium, c.low][i] > 0)
  if (c.other > 0) parts.push(`未分级 ${c.other}`)
  return parts.join(' · ')
}
function riskText(assetKey: string): string {
  const g = reportGroups.value.find(x => x.key === assetKey)
  return g ? riskTextForReport(g.reports[0]) : '—'
}
function complianceTextForReport(r: ReportRow): string {
  const n = complianceFailByReport.value.get(r.id)
  return n === undefined || n === null ? '—' : `不满足 ${n} 条`
}
function complianceText(assetKey: string): string {
  const g = reportGroups.value.find(x => x.key === assetKey)
  return g ? complianceTextForReport(g.reports[0]) : '—'
}
const genMsg = ref('')
const genErr = ref('')
const error = ref('')
const detailId = ref('')
const detail = ref<Record<string, unknown> | null>(null)

const snapshotFindings = computed(() => (detail.value?.findings as Finding[]) || [])
const pathsSection = computed(() => (detail.value?.privilege_paths as ReportPathsSection | undefined) ?? null)
const driftSection = computed(() => (detail.value?.drift as ReportDriftSection | undefined) ?? null)
const remediationSection = computed(() => (detail.value?.remediation as ReportRemediationSection | undefined) ?? null)
const scriptShow = ref(20)
const copyMsg = ref('')
const visibleScripts = computed(() => (remediationSection.value?.scripts || []).slice(0, scriptShow.value))

async function copyText(t: string) {
  try { await navigator.clipboard.writeText(t); copyMsg.value = '已复制' }
  catch { copyMsg.value = '复制失败，请手动选择文本' }
  setTimeout(() => { copyMsg.value = '' }, 2000)
}

async function load() {
  loaded.value = false
  try {
    reports.value = filterByHospital(await api.reports())
    try { latestByAsset.value = new Map(filterByHospital(await api.latestBundles()).map(b => [b.asset_id, b])) } catch { latestByAsset.value = new Map() }
    try { apiReports.value = await api.apiAudits() } catch { apiReports.value = [] }
    try { assets.value = filterByHospital(await api.assets()) } catch { assets.value = [] }
    loaded.value = true
    try {
      const rs = await api.rules()
      rulesMap.value = new Map(rs.map(r => [r.ID, r]))
    } catch { /* 无规则说明时降级 */ }
    try {
      const me = await api.me()
      if (me.username) createdBy.value = me.username
    } catch { /* 未取到登录名时用本地署名 */ }
    if (!genAsset.value && reportableAssets.value.length) {
      genAsset.value = reportableAssets.value[0].id
      await loadGenBundles()
    }
    // 最新报告的问题分级与合规不满足条数（逐份取包问题与报告详情）。
    const rm = new Map<string, { high: number; medium: number; low: number; other: number }>()
    const cm = new Map<string, number | null>()
    for (const g of reportGroups.value) {
      const latest = g.reports[0]
      try {
        const fails = latestFail(await api.findings(latest.bundle_id))
        const c = { high: 0, medium: 0, low: 0, other: 0 }
        for (const f of fails) {
          const r = (rulesMap.value.get(f.rule_id)?.Risk ?? '').toLowerCase()
          if (r === 'high') c.high++
          else if (r === 'medium') c.medium++
          else if (r === 'low') c.low++
          else c.other++
        }
        rm.set(latest.id, c)
      } catch { /* 未评估包 */ }
      try {
        const d = await api.getReport(latest.id)
        const comp = d.compliance as { counts?: Record<string, number> }[] | undefined
        let fail = 0
        let found = false
        if (Array.isArray(comp)) {
          for (const fw of comp) {
            if (fw.counts && typeof fw.counts.fail === 'number') { fail += fw.counts.fail; found = true }
          }
        }
        cm.set(latest.id, found ? fail : null)
      } catch { cm.set(latest.id, null) }
    }
    riskByReport.value = rm
    complianceFailByReport.value = cm
  } catch (e) { error.value = e instanceof Error ? e.message : '加载失败' }
}

// 展开历史时再补算旧报告的问题分级与合规数（平时只算最新一份）。
async function expandHistory(g: ReportGroup) {
  historyOpen.add(g.key)
  for (const r of g.reports.slice(1)) {
    if (!riskByReport.value.has(r.id)) {
      try {
        const fails = latestFail(await api.findings(r.bundle_id))
        const c = { high: 0, medium: 0, low: 0, other: 0 }
        for (const f of fails) {
          const rk = (rulesMap.value.get(f.rule_id)?.Risk ?? '').toLowerCase()
          if (rk === 'high') c.high++
          else if (rk === 'medium') c.medium++
          else if (rk === 'low') c.low++
          else c.other++
        }
        riskByReport.value.set(r.id, c)
      } catch { /* 未评估包 */ }
    }
    if (!complianceFailByReport.value.has(r.id)) {
      try {
        const d = await api.getReport(r.id)
        const comp = d.compliance as { counts?: Record<string, number> }[] | undefined
        let fail = 0
        let found = false
        if (Array.isArray(comp)) {
          for (const fw of comp) {
            if (fw.counts && typeof fw.counts.fail === 'number') { fail += fw.counts.fail; found = true }
          }
        }
        complianceFailByReport.value.set(r.id, found ? fail : null)
      } catch { complianceFailByReport.value.set(r.id, null) }
    }
  }
}

async function generate() {
  genMsg.value = ''; genErr.value = ''
  const b = genBundles.value.find(x => x.id === genBundle.value)
  if (!b) return
  try {
    const r = await api.createReport({
      hospital_id: b.hospital_id, plan_id: b.plan_id, bundle_id: b.id, created_by: createdBy.value,
    })
    genMsg.value = '报告已生成'
    await load()
  } catch (e) { genErr.value = e instanceof Error ? e.message : '生成失败' }
}

async function view(id: string) {
  detailId.value = id
  detail.value = null
  try { detail.value = await api.getReport(id) }
  catch (e) { genErr.value = e instanceof Error ? e.message : '读取失败' }
}

onMounted(load)
</script>
