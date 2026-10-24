<template>
  <div class="card">
    <h2>数据库目标（{{ targets.length }}）</h2>
    <div v-if="error" class="error">{{ error }}</div>
    <table v-else-if="targets.length">
      <thead><tr><th>名称</th><th>类型</th><th>连接</th><th>参数</th><th>最近审计</th><th>操作</th></tr></thead>
      <tbody>
        <tr v-for="a in targets" :key="a.id">
          <td>{{ a.name }}<div class="todo">{{ a.id }} · {{ a.hospital_id }}</div></td>
          <td>{{ engineOfKind(a.kind)?.label ?? a.kind }}</td>
          <td>{{ a.endpoint ?? '—' }}</td>
          <td><span v-if="connOf(a)" class="concl c-PASS">已登记</span><span v-else class="concl c-UNKNOWN">缺参数</span></td>
          <td>
            <template v-if="latestBundle(a.id)">
              {{ fmtLocal(latestBundle(a.id)?.imported_at) }}
              <span v-if="(failOf(a.id) ?? 0) > 0" class="concl c-FAIL">FAIL {{ failOf(a.id) }}</span>
              <span v-else class="concl c-PASS">无问题</span>
              <div class="todo">{{ latestBundle(a.id)?.id }}</div>
            </template>
            <span v-else>未审计</span>
          </td>
          <td>
            <div class="row-actions">
              <button class="btn small primary" :disabled="!connOf(a)" @click="openAudit(a)">开始审计</button>
              <button class="btn small" :disabled="!latestBundle(a.id)" @click="goto('findings', latestBundle(a.id)?.id)">问题</button>
              <button class="btn small" :disabled="!latestBundle(a.id) || exporting === a.id" @click="doExport(a)">导出报告</button>
              <button class="btn small" v-if="bundleCount(a.id) >= 2" @click="gotoAsset('recheck', a.id)">复检对比</button>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty">暂无数据库目标。请工程师在「管理」页登记。</div>
    <div class="msg err" v-if="exportErr">{{ exportErr }}</div>
    <div class="todo" style="margin-top:8px">登记、改参数、删除对象请到「管理」页（工程师）。本页只做审计、看问题、导出报告。</div>
  </div>

  <div class="card" v-if="auditAsset">
    <h2>一键审计：{{ auditAsset.name }}（{{ auditAsset.id }}）</h2>
    <p class="todo">
      将以只读账号 {{ connOf(auditAsset)?.user }} 连接 {{ connOf(auditAsset)?.host }}:{{ connOf(auditAsset)?.port }}
      真实采集权限事实，随后自动评估并生成报告。口令仅本次使用，不保存。
    </p>
    <div class="inline-form">
      <input v-model="auditForm.password" type="password" placeholder="数据库口令" autocomplete="off" style="min-width:220px" />
      <label>基线
        <select v-model="auditForm.baseline_id">
          <option value="">无基线</option>
          <option v-for="b in baselinesOf(auditAsset.hospital_id)" :key="b.id" :value="b.id">{{ b.id }}</option>
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
        评估 {{ result.evaluation.total }} 条结果，FAIL {{ result.evaluation.fail }}，问题落库 {{ result.evaluation.findings_stored }}。
      </p>
      <div class="row-actions">
        <a class="btn primary" :href="api.reportDocxUrl(result.report_id)" download>下载 Word 审计报告</a>
        <button class="btn" @click="goto('findings', result.bundle_id)">查看问题</button>
        <button class="btn" @click="goto('reports')">报告详情</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, type Asset, type AuditRunResult, type BaselineRow, type BundleSummary, type ConnConfig } from '../api'
import { engineOfKind, kindCategory } from '../categories'
import { goto, gotoAsset, reviewerName, filterByHospital } from '../store'
import { exportLatestReport, latestBundleOf, latestFail, fmtLocal} from '../util'

const assets = ref<Asset[]>([])
const bundles = ref<BundleSummary[]>([])
const baselinesMap = ref<Record<string, BaselineRow[]>>({})
const failMap = ref<Map<string, number>>(new Map())
const error = ref('')
const exporting = ref('')
const exportErr = ref('')

const targets = computed(() => assets.value.filter(a => kindCategory(a.kind) === 'db'))

function connOf(a: Asset): ConnConfig | null {
  if (!a.labels) return null
  try {
    const c = JSON.parse(a.labels) as ConnConfig
    return c.host && c.port && c.user ? c : null
  } catch { return null }
}

function latestBundle(assetId: string): BundleSummary | undefined {
  return latestBundleOf(bundles.value, assetId)
}
function bundleCount(assetId: string): number {
  return bundles.value.filter(b => b.asset_id === assetId).length
}
function failOf(assetId: string): number | undefined {
  return failMap.value.get(assetId)
}
function baselinesOf(hospitalId: string): BaselineRow[] {
  return baselinesMap.value[hospitalId] || []
}

async function refreshFails() {
  const m = new Map<string, number>()
  for (const a of targets.value) {
    const lb = latestBundle(a.id)
    if (!lb) continue
    try { m.set(a.id, latestFail(await api.findings(lb.id)).length) } catch { /* 未评估包 */ }
  }
  failMap.value = m
}

async function load() {
  try {
    assets.value = filterByHospital(await api.assets())
    bundles.value = filterByHospital(await api.bundles())
    const hs = filterByHospital(await api.hospitals())
    for (const h of hs) {
      if (!(h.id in baselinesMap.value)) {
        try { baselinesMap.value[h.id] = await api.baselines(h.id) } catch { baselinesMap.value[h.id] = [] }
      }
    }
    await refreshFails()
  } catch (e) { error.value = e instanceof Error ? e.message : '加载失败' }
}

async function doExport(a: Asset) {
  const lb = latestBundle(a.id)
  if (!lb) return
  exporting.value = a.id; exportErr.value = ''
  try { await exportLatestReport(lb) }
  catch (e) { exportErr.value = e instanceof Error ? e.message : '导出失败' }
  finally { exporting.value = '' }
}

// ---- 一键审计 ----
const auditAsset = ref<Asset | null>(null)
const auditForm = ref({ password: '', baseline_id: '', created_by: reviewerName() })
const running = ref(false)
const auditErr = ref('')
const result = ref<AuditRunResult | null>(null)

function openAudit(a: Asset) {
  auditAsset.value = a
  auditForm.value = { password: '', baseline_id: '', created_by: reviewerName() }
  auditErr.value = ''
  result.value = null
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
    bundles.value = filterByHospital(await api.bundles())
    await refreshFails()
  } catch (e) {
    auditErr.value = e instanceof Error ? e.message : '审计失败'
  } finally { running.value = false }
}

onMounted(load)
</script>
