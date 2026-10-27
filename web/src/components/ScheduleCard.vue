<template>
  <div class="card">
    <h2>定期自动复检（已开启 {{ items.length }}）</h2>
    <div class="msg err" v-if="!keyReady">服务端未配置证据密钥（MEDAUDIT_EVIDENCE_KEY），口令无法加密保存，暂不能开启。</div>
    <table v-if="rows.length">
      <thead><tr><th>对象</th><th>状态</th><th>下次执行</th><th>上次结果</th><th>操作</th></tr></thead>
      <tbody>
        <tr v-for="r in rows" :key="r.a.id">
          <td>{{ r.a.name }}<div class="todo">{{ r.a.id }}</div></td>
          <td>
            <span v-if="r.s" class="concl c-PASS">每 {{ r.s.cycle_days }} 天</span>
            <span v-else class="concl c-UNKNOWN">未开启</span>
          </td>
          <td>{{ r.s ? fmtLocal(r.s.next_run_at) : '—' }}</td>
          <td>
            <template v-if="r.s?.last_status === 'ok'"><span class="concl c-PASS">成功</span> <span class="todo">{{ fmtLocal(r.s.last_run_at) }}</span></template>
            <template v-else-if="r.s?.last_status === 'failed'"><span class="concl c-FAIL">失败</span><div class="todo">{{ r.s.last_error }}</div></template>
            <span v-else-if="r.s?.last_status === 'running'" class="concl c-UNKNOWN">执行中…</span>
            <span v-else>—</span>
          </td>
          <td>
            <div class="row-actions">
              <button class="btn small" :class="{ primary: !r.s }" :disabled="!keyReady" @click="edit(r.a.id, r.s)">{{ r.s ? '修改' : '开启' }}</button>
              <button v-if="r.s" class="btn small" :disabled="r.s.last_status === 'running'" @click="runNow(r.a.id)">立即执行</button>
              <button v-if="r.s" class="btn small" @click="turnOff(r.a.id)">关闭</button>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty">暂无可自动复检的对象（支持已登记连接参数的数据库、Linux/Windows/HP-UX 主机与中间件）。</div>

    <div class="inline-form" v-if="editing" style="margin-top:10px">
      <span>{{ editing }}：</span>
      <label>每
        <select v-model.number="form.cycle">
          <option :value="7">7</option><option :value="14">14</option><option :value="30">30</option>
          <option :value="60">60</option><option :value="90">90</option>
        </select> 天
      </label>
      <input v-model="form.password" type="password" autocomplete="new-password"
        :placeholder="editingExisting ? '目标登录口令（不改可留空）' : '目标登录口令（必填）'" style="min-width:240px" />
      <button class="btn primary small" @click="save">保存</button>
      <button class="btn small" @click="editing = ''">取消</button>
    </div>
    <div class="msg" v-if="msg">{{ msg }}</div>
    <div class="msg err" v-if="err">{{ err }}</div>
    <div class="todo">开启后平台按周期自动审计、自动套用本院基线并生成报告；有新增权限或执行失败会出现在工作台「告警」。开启时口令经证据密钥加密保存在平台库，只在执行时解密使用；点「关闭」立即删除保存的口令。未开启的对象口令仍然不落库。</div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { api, type Asset, type ScheduleRow } from '../api'
import { fmtLocal } from '../util'
import { filterByHospital } from '../store'

const SUPPORTED = /^(db-(mysql|sqlserver|oracle|postgres)|os-(linux|windows|hpux)|mw-(tomcat|nginx|weblogic|iis))$/

const assets = ref<Asset[]>([])
const items = ref<ScheduleRow[]>([])
const keyReady = ref(true)
const editing = ref('')
const editingExisting = ref(false)
const form = reactive({ cycle: 30, password: '' })
const msg = ref('')
const err = ref('')

const rows = computed(() => {
  const byId = new Map(items.value.map(s => [s.asset_id, s]))
  return filterByHospital(assets.value)
    .filter(a => SUPPORTED.test(a.kind) && a.labels)
    .map(a => ({ a, s: byId.get(a.id) }))
    .sort((x, y) => Number(!!y.s) - Number(!!x.s) || x.a.id.localeCompare(y.a.id))
})

function edit(id: string, s?: ScheduleRow) {
  editing.value = id
  editingExisting.value = !!s
  form.cycle = s?.cycle_days ?? 30
  form.password = ''
  msg.value = ''; err.value = ''
}

async function wrap(fn: () => Promise<unknown>, ok: string) {
  msg.value = ''; err.value = ''
  try { await fn(); msg.value = ok; await load() }
  catch (e) { err.value = e instanceof Error ? e.message : String(e) }
}

function save() {
  const id = editing.value
  return wrap(async () => {
    await api.saveSchedule(id, { cycle_days: form.cycle, password: form.password || undefined })
    editing.value = ''
    form.password = ''
  }, `已保存：${id} 每 ${form.cycle} 天自动复检`)
}

function runNow(id: string) {
  return wrap(() => api.runSchedule(id), `已开始复检 ${id}，完成后刷新查看结果`)
}

function turnOff(id: string) {
  if (!confirm(`关闭 ${id} 的定期自动复检并删除保存的口令？`)) return
  return wrap(() => api.deleteSchedule(id), `已关闭 ${id}，保存的口令已删除`)
}

async function load() {
  const [as, sc] = await Promise.all([api.assets(), api.schedules()])
  assets.value = as
  items.value = sc.items
  keyReady.value = sc.key_ready
}

onMounted(() => load().catch(e => { err.value = e instanceof Error ? e.message : String(e) }))
</script>
