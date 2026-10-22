<template>
  <div class="card">
    <h2>业务接口登记</h2>
    <div class="form-grid">
      <label>资产 ID<input v-model="form.id" placeholder="api-his-01" /></label>
      <label>医院
        <select v-model="form.hospital_id">
          <option v-for="h in hospitals" :key="h.id" :value="h.id">{{ h.id }}（{{ h.name }}）</option>
        </select>
      </label>
      <label>名称<input v-model="form.name" placeholder="如：HIS 业务接口" /></label>
      <label>基础地址<input v-model="form.endpoint" placeholder="https://his.example.internal/api" /></label>
    </div>
    <div class="inline-form">
      <button class="btn primary" @click="create">登记接口</button>
      <span class="msg" v-if="msg">{{ msg }}</span>
      <span class="msg err" v-if="err">{{ err }}</span>
    </div>
    <div class="todo">
      越权检测在采集端执行：<code>medaudit-collector apicheck --config &lt;配置.yml&gt; --out report.json --upload {{ origin }}</code>
      （配置含目标地址、测试身份与权限期望模型，身份凭据经环境变量注入不落文件）。
      检测报告回传后在下方查看，并可下载 Word 版报告。
    </div>
    <table v-if="targets.length" style="margin-top:10px">
      <thead><tr><th>名称</th><th>基础地址</th><th>医院</th></tr></thead>
      <tbody>
        <tr v-for="a in targets" :key="a.id">
          <td>{{ a.name }}<div class="todo">{{ a.id }}</div></td>
          <td>{{ a.endpoint ?? '—' }}</td><td>{{ a.hospital_id }}</td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>越权检测报告</h2>
    <div v-if="error" class="error">{{ error }}</div>
    <table v-else-if="list.length">
      <thead><tr><th>报告</th><th>目标</th><th>执行</th><th>探针</th><th>通过</th><th>失败</th><th>未知</th><th>未跑</th><th>导入时间</th><th>操作</th></tr></thead>
      <tbody>
        <tr v-for="a in list" :key="a.report_id" class="clickable" :class="{ selected: detailId === a.report_id }" @click="view(a.report_id)">
          <td>{{ a.report_id }}</td><td>{{ a.target }}</td><td>{{ a.execution }}</td><td>{{ a.total }}</td>
          <td>{{ a.pass_count }}</td>
          <td><span v-if="a.fail_count" class="concl c-FAIL">{{ a.fail_count }}</span><span v-else>0</span></td>
          <td>{{ a.unknown_count }}</td><td>{{ a.not_run_count }}</td><td>{{ fmtLocal(a.imported_at) }}</td>
          <td><a class="btn small" :href="api.apiAuditDocxUrl(a.report_id)" download @click.stop>Word</a></td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty">暂无越权检测报告。用采集器 apicheck 命令生成并回传。</div>
  </div>

  <div class="card" v-if="detail">
    <h2>逐项探针（{{ detailId }}）</h2>
    <table v-if="detail.checks?.length">
      <thead><tr><th>端点</th><th>身份</th><th>期望模型</th><th>探针</th><th>状态码</th><th>结论</th><th>说明</th></tr></thead>
      <tbody>
        <tr v-for="(c, i) in detail.checks" :key="i">
          <td><code>{{ c.endpoint }}</code></td><td>{{ c.identity }}</td><td>{{ c.expectation }}</td>
          <td>{{ c.probe }}</td><td>{{ c.status }}</td>
          <td><span class="concl" :class="'c-' + c.conclusion">{{ c.conclusion }}</span></td>
          <td style="font-size:13px">{{ c.detail }}</td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty">该报告无逐项数据。</div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, type ApiAuditCheck, type ApiAuditSummary, type Asset, type Hospital } from '../api'
import { fmtLocal } from '../util'
import { kindCategory } from '../categories'

const hospitals = ref<Hospital[]>([])
const assets = ref<Asset[]>([])
const list = ref<ApiAuditSummary[]>([])
const error = ref('')
const msg = ref('')
const err = ref('')
const detailId = ref('')
const detail = ref<{ checks: ApiAuditCheck[] } | null>(null)
const form = ref({ id: '', hospital_id: '', name: '', endpoint: '' })
const origin = window.location.origin

const targets = computed(() => assets.value.filter(a => kindCategory(a.kind) === 'api'))

async function load() {
  try {
    hospitals.value = await api.hospitals()
    assets.value = await api.assets()
    list.value = await api.apiAudits()
    if (!form.value.hospital_id && hospitals.value.length) form.value.hospital_id = hospitals.value[0].id
  } catch (e) { error.value = e instanceof Error ? e.message : '加载失败' }
}

async function create() {
  msg.value = ''; err.value = ''
  try {
    await api.createAsset({
      id: form.value.id, hospital_id: form.value.hospital_id, kind: 'api',
      name: form.value.name, endpoint: form.value.endpoint || null,
      labels: JSON.stringify({ base_url: form.value.endpoint }),
    })
    msg.value = `接口 ${form.value.id} 已登记`
    form.value.id = ''; form.value.name = ''
    await load()
  } catch (e) { err.value = e instanceof Error ? e.message : '登记失败' }
}

async function view(id: string) {
  detailId.value = id
  detail.value = null
  try { detail.value = await api.getApiAudit(id) }
  catch (e) { error.value = e instanceof Error ? e.message : '读取失败' }
}

onMounted(load)
</script>
