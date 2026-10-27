<template>
  <div class="card">
    <h2>发起关联分析</h2>
    <p class="todo" style="margin-top:0">
      选择同一医院的 2 个以上事实包（应为同一主机的不同层面：操作系统 + 中间件 + 数据库），
      系统将把它们建成权限图，搜索低权账号到 root / 数据库超级账号的提权路径。每一步都附证据事实。
    </p>
    <div v-if="error" class="error">{{ error }}</div>
    <div v-for="h in hospitalsWithBundles" :key="h" style="margin-bottom:10px">
      <div style="font-weight:600;margin-bottom:4px">{{ h }}</div>
      <label v-for="b in bundlesByHospital(h)" :key="b.id" style="display:block;font-weight:400;margin:2px 0">
        <input type="checkbox" :value="b.id" v-model="selected" />
        {{ b.id }} <span class="todo">{{ b.adapter }} · {{ b.asset_id }} · {{ fmtLocal(b.imported_at) }}</span>
      </label>
    </div>
    <div class="inline-form">
      <button class="btn primary" :disabled="selected.length < 2 || running" @click="run">运行关联分析（已选 {{ selected.length }}）</button>
      <span class="msg err" v-if="runErr">{{ runErr }}</span>
    </div>
  </div>

  <div class="card" v-if="detail">
    <h2>分析结果 · {{ detail.report_id }}</h2>
    <p class="todo">图规模：{{ detail.result.nodes }} 节点 / {{ detail.result.edges }} 边；提权路径 {{ detail.path_count }} 条</p>
    <div v-if="!detail.result.paths.length" class="empty">未发现提权路径（在已采集事实范围内）。</div>
    <div v-for="(p, i) in detail.result.paths" :key="i" style="margin:10px 0;padding:10px;border:1px solid #e5e7eb;border-radius:8px">
      <div>
        <span class="concl" :class="p.risk === 'high' ? 'c-FAIL' : 'c-UNKNOWN'">{{ p.risk === 'high' ? '高' : '中' }}</span>
        <b>{{ p.source }}</b> → <b>{{ p.target }}</b>
        <span class="todo">（{{ p.hops.length }} 步）</span>
      </div>
      <div style="margin-top:6px;font-family:monospace;font-size:13px;line-height:1.9">
        <span v-for="(h, j) in p.hops" :key="j">
          {{ h.from }} <span style="color:#2563eb">—{{ h.action }}→</span>
          <span v-if="j === p.hops.length - 1">{{ h.to }}</span>
        </span>
      </div>
      <div class="todo">证据：{{ detail.result.paths[i].hops.map(h => h.evidence.join(',')).join(' · ') }}</div>
    </div>
  </div>

  <div class="card">
    <h2>历史关联报告（{{ history.length }}）</h2>
    <table v-if="history.length">
      <thead><tr><th>报告</th><th>医院</th><th>事实包数</th><th>路径数</th><th>时间</th><th>操作</th></tr></thead>
      <tbody>
        <tr v-for="c in history" :key="c.report_id">
          <td>{{ c.report_id }}</td>
          <td>{{ c.hospital_id }}</td>
          <td>{{ c.bundle_ids.length }}</td>
          <td>{{ c.path_count }}</td>
          <td>{{ fmtLocal(c.created_at) }}</td>
          <td><button class="btn small" @click="open(c.report_id)">查看</button></td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty">暂无关联报告。</div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, type BundleSummary, type CorrelationDetail, type CorrelationSummary } from '../api'
import { fmtLocal } from '../util'
import { filterByHospital } from '../store'

const bundles = ref<BundleSummary[]>([])
const history = ref<CorrelationSummary[]>([])
const selected = ref<string[]>([])
const detail = ref<CorrelationDetail | null>(null)
const error = ref('')
const runErr = ref('')
const running = ref(false)

const hospitalsWithBundles = computed(() => [...new Set(bundles.value.map(b => b.hospital_id))])
function bundlesByHospital(h: string): BundleSummary[] {
  return bundles.value.filter(b => b.hospital_id === h)
}

async function load() {
  try {
    bundles.value = filterByHospital(await api.bundles())
    history.value = filterByHospital(await api.correlations())
  } catch (e) { error.value = e instanceof Error ? e.message : '加载失败' }
}

async function run() {
  runErr.value = ''
  running.value = true
  try {
    detail.value = await api.runCorrelation(selected.value)
    history.value = filterByHospital(await api.correlations())
  } catch (e) { runErr.value = e instanceof Error ? e.message : '分析失败' }
  running.value = false
}

async function open(id: string) {
  try { detail.value = await api.correlation(id) } catch (e) { runErr.value = e instanceof Error ? e.message : '打开失败' }
}

onMounted(load)
</script>
