<template>
  <div class="card">
    <h2>主机目标（{{ targets.length }}）</h2>
    <div v-if="error" class="error">{{ error }}</div>
    <table v-else-if="targets.length">
      <thead><tr><th>名称</th><th>地址</th><th>最近审计</th><th>操作</th></tr></thead>
      <tbody>
        <template v-for="a in targets" :key="a.id">
          <tr>
            <td>{{ a.name }}<div class="todo">{{ a.id }} · {{ a.hospital_id }}</div></td>
            <td>{{ a.endpoint ?? '—' }}</td>
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
                <button class="btn small primary" v-if="remoteOf(a)" @click="remoteAsset = remoteAsset?.id === a.id ? null : a">开始审计（远程）</button>
                <button class="btn small" @click="guideFor = guideFor === a.id ? '' : a.id">采集指引</button>
                <button class="btn small" :disabled="!latestBundle(a.id)" @click="goto('findings', latestBundle(a.id)?.id)">问题</button>
                <button class="btn small" :disabled="!latestBundle(a.id) || exporting === a.id" @click="doExport(a)">导出报告</button>
                <button class="btn small" v-if="bundleCount(a.id) >= 2" @click="gotoAsset('recheck', a.id)">复检对比</button>
              </div>
            </td>
          </tr>
          <tr v-if="guideFor === a.id">
            <td colspan="4">
              <p style="margin:4px 0">在目标主机上以 root（Linux）/ 管理员（Windows）运行：</p>
              <pre>{{ commandFor(a) }}</pre>
              <p class="todo" style="margin:4px 0">
                Windows 使用 medaudit-collector.exe，参数相同。采集完成后事实包自动回传本平台；
                也可在「审计记录」页手动上传 bundle-os.zip，再在工程师详情里点「评估」。
              </p>
            </td>
          </tr>
        </template>
      </tbody>
    </table>
    <div v-else class="empty">暂无主机目标。请工程师在「管理」页登记。</div>
    <div class="msg err" v-if="exportErr">{{ exportErr }}</div>
    <div class="todo" style="margin-top:8px">登记、改参数、删除对象请到「管理」页（工程师）。登记了远程参数的主机可由服务端推送采集器远程审计：口令在审计时输入、仅本次使用不保存。</div>
  </div>

  <RemoteAuditCard :asset="remoteAsset" @close="remoteAsset = null" @done="load" />
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, parseRemote, type Asset, type BundleSummary } from '../api'
import RemoteAuditCard from '../components/RemoteAuditCard.vue'
import { kindCategory } from '../categories'
import { goto, gotoAsset, filterByHospital } from '../store'
import { exportLatestReport, latestBundleOf, latestFail, fmtLocal} from '../util'

const assets = ref<Asset[]>([])
const bundles = ref<BundleSummary[]>([])
const failMap = ref<Map<string, number>>(new Map())
const error = ref('')
const guideFor = ref('')
const exporting = ref('')
const exportErr = ref('')
const remoteAsset = ref<Asset | null>(null)

function remoteOf(a: Asset) { return parseRemote(a) }

const targets = computed(() => assets.value.filter(a => kindCategory(a.kind) === 'os'))

function latestBundle(assetId: string): BundleSummary | undefined {
  return latestBundleOf(bundles.value, assetId)
}
function bundleCount(assetId: string): number {
  return bundles.value.filter(b => b.asset_id === assetId).length
}
function failOf(assetId: string): number | undefined {
  return failMap.value.get(assetId)
}

function commandFor(a: Asset): string {
  const origin = window.location.origin
  const exe = 'medaudit-collector'
  return [
    `${exe} os --out bundle-os.zip --hospital ${a.hospital_id} --asset ${a.id} --plan plan-web-${a.id}`,
    `${exe} bundle upload --file bundle-os.zip --server ${origin}`,
  ].join('\n')
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

async function doExport(a: Asset) {
  const lb = latestBundle(a.id)
  if (!lb) return
  exporting.value = a.id; exportErr.value = ''
  try { await exportLatestReport(lb) }
  catch (e) { exportErr.value = e instanceof Error ? e.message : '导出失败' }
  finally { exporting.value = '' }
}

async function load() {
  try {
    assets.value = filterByHospital(await api.assets())
    bundles.value = filterByHospital(await api.bundles())
    await refreshFails()
  } catch (e) { error.value = e instanceof Error ? e.message : '加载失败' }
}

onMounted(load)
</script>
