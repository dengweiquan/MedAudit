<template>
  <div class="card">
    <h2>生成报告</h2>
    <div class="inline-form">
      <label>对象
        <select v-model="genAsset" @change="genBundle = latestBundleOfAsset(genAsset)?.id ?? ''">
          <option v-for="a in reportableAssets" :key="a.id" :value="a.id">{{ a.name }}（{{ a.id }}）</option>
        </select>
      </label>
      <label>审计记录
        <select v-model="genBundle">
          <option v-for="b in bundlesOfAsset(genAsset)" :key="b.id" :value="b.id">{{ fmtLocal(b.imported_at) }}（{{ b.id }}）</option>
        </select>
      </label>
      <button class="btn primary" :disabled="!genBundle" @click="generate">生成报告</button>
      <span class="msg" v-if="genMsg">{{ genMsg }}</span>
      <span class="msg err" v-if="genErr">{{ genErr }}</span>
    </div>
    <div class="todo">默认对对象的最近一次审计生成；生成人自动记为当前登录账号（{{ createdBy || '—' }}）。</div>
  </div>

  <div class="card">
    <h2>报告列表（按对象）</h2>
    <div v-if="error" class="error">{{ error }}</div>
    <div v-else-if="!reportGroups.length" class="empty">暂无报告。</div>
    <template v-for="g in reportGroups" :key="g.key">
      <h3 style="margin:14px 0 6px">{{ g.name }} <span class="todo">{{ g.key }} · 共 {{ g.reports.length }} 份</span></h3>
      <table>
        <thead><tr><th>生成时间</th><th>结论摘要</th><th>生成人</th><th>审计记录</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="r in visibleReports(g)" :key="r.id" :class="{ selected: detailId === r.id }">
            <td>{{ fmtLocal(r.created_at) }}<div class="todo">{{ r.id }}</div></td>
            <td>
              <span v-for="(n, c) in r.conclusion_summary || {}" :key="c" class="concl" :class="'c-' + c" style="margin-right:4px">{{ c }} {{ n }}</span>
            </td>
            <td>{{ r.created_by }}</td>
            <td>{{ r.bundle_id }}</td>
            <td>
              <div class="row-actions">
                <button class="btn small" @click="view(r.id)">查看</button>
                <a class="btn small" :href="api.reportDocxUrl(r.id)" download>Word</a>
                <a class="btn small" :href="api.reportCsvUrl(r.id)" download>CSV</a>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <button v-if="g.reports.length > 1 && !historyOpen.has(g.key)" class="btn small" @click="historyOpen.add(g.key)">
        显示历史报告（{{ g.reports.length - 1 }} 份）
      </button>
    </template>
  </div>

  <div class="card" v-if="detail">
    <h2>报告详情（{{ detailId }}）</h2>
    <p>
      结论摘要：
      <span v-for="(n, c) in (detail.conclusion_summary as Record<string, number>) || {}" :key="c"
            class="concl" :class="'c-' + c" style="margin-right:4px">{{ c }} {{ n }}</span>
      <span class="todo">执行 {{ detail.execution }} · 适配器 {{ detail.adapter }}</span>
    </p>
    <h3>覆盖（coverage）</h3>
    <pre>{{ JSON.stringify(detail.coverage ?? detail.coverage_note ?? '（旧报告无覆盖数据）', null, 2) }}</pre>
    <template v-if="pathsSection">
      <h3>跨层提权路径（关联分析）</h3>
      <p class="todo">
        来源关联报告 {{ pathsSection.correlation_report_id }}（{{ pathsSection.generated_at }}）；
        提权路径共 {{ pathsSection.path_count }} 条{{ pathsSection.paths.length < pathsSection.path_count ? `，此处列 ${pathsSection.paths.length} 条` : '' }}。
      </p>
      <table v-if="pathsSection.paths.length">
        <thead><tr><th>风险</th><th>路径链</th></tr></thead>
        <tbody>
          <tr v-for="(p, i) in pathsSection.paths" :key="i">
            <td><span class="concl" :class="p.risk === 'high' ? 'c-FAIL' : 'c-UNKNOWN'">{{ p.risk }}</span></td>
            <td>{{ p.chain }}</td>
          </tr>
        </tbody>
      </table>
      <div v-else class="empty">该关联报告未发现提权路径。</div>
    </template>
    <template v-if="driftSection">
      <h3>权限漂移（与上一事实包对比）</h3>
      <p class="todo">
        基线包 {{ driftSection.base_id }}；新增 {{ driftSection.added_total }} 项、消失 {{ driftSection.removed_total }} 项，
        其中 <b style="color:#b91c1c">新增授权/角色关系 {{ driftSection.attention }} 项</b>需重点关注。
      </p>
      <table v-if="driftSection.added.length || driftSection.removed.length">
        <thead><tr><th>方向</th><th>类别</th><th>主体</th><th>明细</th></tr></thead>
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
        FAIL 共 {{ remediationSection.fail_total }} 条，已生成脚本 {{ remediationSection.generated }} 条
        （快照存入 {{ remediationSection.stored }} 条）；未生成的为程序性整改项。脚本仅供人工评审后执行，平台不自动修改目标权限。
      </p>
      <div v-for="(s, i) in visibleScripts" :key="s.finding_id" class="fixscript">
        <details>
          <summary><b>{{ s.rule_id }}</b> · {{ s.subject }}<span v-if="s.scope"> · {{ s.scope }}</span></summary>
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
      <thead><tr><th>规则</th><th>主体</th><th>结论</th><th>复核</th></tr></thead>
      <tbody>
        <tr v-for="f in snapshotFindings" :key="f.id">
          <td>{{ f.rule_id }}</td><td>{{ f.subject }}</td>
          <td><span class="concl" :class="'c-' + f.conclusion">{{ f.conclusion }}</span></td>
          <td>{{ f.review_status }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { api, type Asset, type BundleSummary, type Finding, type ReportDriftSection, type ReportPathsSection, type ReportRemediationSection, type ReportRow } from '../api'
import { fmtLocal } from '../util'
import { reviewerName, filterByHospital } from '../store'

const bundles = ref<BundleSummary[]>([])
const assets = ref<Asset[]>([])
const reports = ref<ReportRow[]>([])
const genAsset = ref('')
const genBundle = ref('')
const createdBy = ref(reviewerName())
const historyOpen = reactive(new Set<string>())

const reportableAssets = computed(() => assets.value.filter(a => bundles.value.some(b => b.asset_id === a.id)))
function bundlesOfAsset(assetId: string): BundleSummary[] {
  return bundles.value.filter(b => b.asset_id === assetId)
}
function latestBundleOfAsset(assetId: string): BundleSummary | undefined {
  const list = bundlesOfAsset(assetId)
  return list.length ? list[list.length - 1] : undefined
}

interface ReportGroup { key: string; name: string; reports: ReportRow[] }
const reportGroups = computed<ReportGroup[]>(() => {
  const bundleAsset = new Map(bundles.value.map(b => [b.id, b.asset_id]))
  const byKey = new Map<string, ReportRow[]>()
  for (const r of reports.value) {
    const key = bundleAsset.get(r.bundle_id) ?? r.bundle_id
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
function visibleReports(g: ReportGroup): ReportRow[] {
  return historyOpen.has(g.key) ? g.reports : g.reports.slice(0, 1)
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
  try {
    reports.value = filterByHospital(await api.reports())
    bundles.value = filterByHospital(await api.bundles())
    try { assets.value = filterByHospital(await api.assets()) } catch { assets.value = [] }
    try {
      const me = await api.me()
      if (me.username) createdBy.value = me.username
    } catch { /* 未取到登录名时用本地署名 */ }
    if (!genAsset.value && reportableAssets.value.length) {
      genAsset.value = reportableAssets.value[0].id
      genBundle.value = latestBundleOfAsset(genAsset.value)?.id ?? ''
    }
  } catch (e) { error.value = e instanceof Error ? e.message : '加载失败' }
}

async function generate() {
  genMsg.value = ''; genErr.value = ''
  const b = bundles.value.find(x => x.id === genBundle.value)
  if (!b) return
  try {
    const r = await api.createReport({
      hospital_id: b.hospital_id, plan_id: b.plan_id, bundle_id: b.id, created_by: createdBy.value,
    })
    genMsg.value = `报告已生成：${r.report_id}`
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
