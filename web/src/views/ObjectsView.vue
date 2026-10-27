<template>
  <div class="card">
    <h2>审计对象（{{ assets.length }}）</h2>
    <div v-if="error" class="error">{{ error }}</div>
    <table v-else-if="assets.length">
      <thead><tr><th>对象名称</th><th>类别</th><th>上次审计</th><th>问题</th><th>操作</th></tr></thead>
      <tbody>
        <tr v-for="a in assets" :key="a.id">
          <td>{{ a.name }}</td>
          <td>{{ catLabel(kindCategory(a.kind)) }}</td>
          <td>
            <template v-if="latestBundle(a.id)">
              {{ fmtLocal(latestBundle(a.id)?.imported_at) }}
              <span v-if="(failOf(a.id) ?? 0) > 0" class="concl c-FAIL">不通过 {{ failOf(a.id) }} 项</span>
              <span v-else class="concl c-PASS">通过</span>
            </template>
            <span v-else>未审计</span>
          </td>
          <td>
            <span v-if="latestBundle(a.id)">{{ failOf(a.id) ?? 0 }} 项不通过</span>
            <span v-else>—</span>
          </td>
          <td>
            <div class="row-actions">
              <button class="btn small primary" @click="gotoAsset(viewOfKind(a.kind), a.id)">开始审计</button>
              <button class="btn small" :disabled="!latestBundle(a.id)" @click="goto('findings', latestBundle(a.id)?.id)">看问题</button>
              <button class="btn small" :disabled="!latestBundle(a.id) || exporting === a.id" @click="doExport(a)">导出报告</button>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty">暂无审计对象。请工程师在「管理」页登记。</div>
    <div class="msg err" v-if="exportErr">{{ exportErr }}</div>
    <div class="todo" style="margin-top:8px">登记、改参数、删除对象请到「管理」页（工程师）。本页只做审计、看问题、导出报告。</div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, type Asset, type BundleSummary } from '../api'
import { kindCategory, type CategoryKey } from '../categories'
import { goto, gotoAsset, filterByHospital } from '../store'
import { exportLatestReport, latestBundleOf, latestFail, fmtLocal } from '../util'

const assets = ref<Asset[]>([])
const bundles = ref<BundleSummary[]>([])
const failMap = ref<Map<string, number>>(new Map())
const error = ref('')
const exporting = ref('')
const exportErr = ref('')

function catLabel(c: CategoryKey | 'unknown'): string {
  return { db: '数据库', os: '操作系统', mw: '中间件', api: '业务接口', unknown: '未分类' }[c]
}
function viewOfKind(kind: string): string {
  return { db: 'databases', os: 'os', mw: 'middleware', api: 'api' }[kindCategory(kind) as string] ?? 'admin'
}
function latestBundle(assetId: string): BundleSummary | undefined {
  return latestBundleOf(bundles.value, assetId)
}
function failOf(assetId: string): number | undefined {
  return failMap.value.get(assetId)
}

async function load() {
  try {
    assets.value = filterByHospital(await api.assets())
    bundles.value = filterByHospital(await api.bundles())
    const m = new Map<string, number>()
    for (const a of assets.value) {
      const lb = latestBundle(a.id)
      if (!lb) continue
      try { m.set(a.id, latestFail(await api.findings(lb.id)).length) } catch { /* 未评估包 */ }
    }
    failMap.value = m
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

onMounted(load)
</script>
