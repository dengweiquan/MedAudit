<template>
  <TemplateCard :hospital-id="hospitalId" @applied="load" />

  <div class="card">
    <h2>基线（按医院）</h2>
    <div class="inline-form">
      <label>医院
        <select v-model="hospitalId" @change="load">
          <option v-for="h in hospitals" :key="h.id" :value="h.id">{{ h.id }}（{{ h.name }}）</option>
        </select>
      </label>
    </div>
    <div v-if="error" class="error">{{ error }}</div>
    <table v-else-if="baselines.length">
      <thead><tr><th>ID</th><th>目标</th><th>版本</th><th>允许清单</th><th>操作</th></tr></thead>
      <tbody>
        <tr v-for="b in baselines" :key="b.id">
          <td>{{ b.id }}</td><td>{{ b.target }}</td><td>{{ b.version }}</td>
          <td>
            <div v-for="(a, i) in allowsOf(b)" :key="i" style="font-size:13px">
              {{ a.subject }} · {{ baselineKindLabel(a.kind) }} = {{ a.value }} <span class="todo">scope {{ a.scope }}{{ a.reason ? ' · ' + a.reason : '' }}</span>
              <button class="btn small" title="删除这条放行项" @click="removeAllow(b, a)">删除</button>
            </div>
            <span v-if="!allowsOf(b).length" class="todo">（空）</span>
          </td>
          <td>
            <button class="btn small" title="编辑这条基线的放行项" @click="startEdit(b)">编辑</button>
            <button class="btn small" title="删除整条基线" @click="deleteBaselineRow(b)">删除</button>
          </td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty">该医院暂无基线。</div>
  </div>

  <div class="card">
    <h2>{{ editingId ? `编辑基线 ${editingId}` : '新建基线' }}</h2>
    <p class="todo" v-if="editingId" style="margin:6px 0">编辑只改放行项：基线 ID、医院、目标锁定不动；保存后版本号 +1，已存的问题与报告不动，之后的评估用新放行项。</p>
    <div class="form-grid">
      <label>基线 ID<input v-model="form.id" placeholder="bl-prod-1" :disabled="!!editingId" /></label>
      <label>医院
        <select v-model="form.hospital_id" :disabled="!!editingId">
          <option v-for="h in hospitals" :key="h.id" :value="h.id">{{ h.id }}</option>
        </select>
      </label>
      <label>目标
        <select v-model="form.target" :disabled="!!editingId">
          <option v-for="t in targets" :key="t" :value="t">{{ t }}</option>
        </select>
      </label>
      <label>创建人<input v-model="form.created_by" placeholder="创建人" /></label>
    </div>
    <p class="todo" style="margin:6px 0">放行项一条 = 放行某个账号的一项权限/角色/身份。<span title="逐项填写后点「添加一条」，可加多条再一次创建。更推荐：到「问题」页对具体问题点「加入基线」，放行项由系统按证据自动推导，不必手填。">?</span></p>
    <div class="form-grid">
      <label>账号/角色/对象<input v-model="draft.subject" :placeholder="subjectHint" /></label>
      <label>种类
        <select v-model="draft.kind">
          <option v-for="k in kindOptions" :key="k.v" :value="k.v">{{ k.label }}（{{ k.v }}）</option>
        </select>
      </label>
      <label>值<input v-model="draft.value" :placeholder="valueHint" /></label>
      <label>范围 scope（可空）<input v-model="draft.scope" placeholder="如 *.*，多数情况留空" /></label>
      <label>原因<input v-model="draft.reason" placeholder="业务依据（必填思路：为何可放行）" /></label>
    </div>
    <div class="inline-form">
      <button class="btn" @click="addDraft">添加一条</button>
      <span class="todo" v-if="!draftAllows.length">尚未添加放行项。</span>
    </div>
    <div v-for="(a, i) in draftAllows" :key="i" style="font-size:13px">
      {{ a.subject }} · {{ baselineKindLabel(a.kind) }} = {{ a.value }} <span class="todo">scope {{ a.scope }}{{ a.reason ? ' · ' + a.reason : '' }}</span>
      <button class="btn small" @click="draftAllows.splice(i, 1)">移除</button>
    </div>
    <details style="margin-top:8px">
      <summary class="todo">高级：直接粘贴 JSON 数组（填写后优先于上面的逐条添加）</summary>
      <textarea v-model="form.allowsText" rows="4" spellcheck="false"
        placeholder='[{"subject":"root@localhost","kind":"privilege","value":"SUPER","scope":"*.*","reason":"测试环境管理"}]'></textarea>
    </details>
    <div class="inline-form" style="margin-top:8px">
      <button class="btn primary" v-if="!editingId" @click="create">创建基线</button>
      <button class="btn primary" v-if="editingId" @click="saveEdit">保存修改</button>
      <button class="btn" v-if="editingId" @click="cancelEdit">取消编辑</button>
      <span class="msg" v-if="msg">{{ msg }}</span>
      <span class="msg err" v-if="err">{{ err }}</span>
    </div>
    <div class="todo">基线只豁免技术结论，不改写事实；评估时在「审计记录」页对应记录的「工程师详情」里选择基线后点评估。放行项的种类与值须与检查口径一致（例：MySQL 全局权限放行填 种类=权限、值=SUPER、范围=*.*）。</div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { selectedHospital } from '../store'
import { api, type BaselineRow, type Hospital } from '../api'
import { reviewerName } from '../store'
import { loadSite, baselineKindLabel } from '../util'
import TemplateCard from '../components/TemplateCard.vue'

interface Allow { subject: string; kind: string; value: string; scope: string; reason?: string }

const hospitals = ref<Hospital[]>([])
const hospitalId = ref('')
const baselines = ref<BaselineRow[]>([])
const error = ref('')
const msg = ref('')
const err = ref('')
const targets = ['db-oracle', 'db-mysql', 'db-sqlserver', 'db-postgres', 'os-linux', 'os-windows', 'os-hpux', 'mw-tomcat', 'mw-nginx', 'mw-weblogic', 'mw-iis']
const form = ref({
  id: '', hospital_id: '', target: 'db-mysql', created_by: reviewerName(),
  allowsText: '',
})

// 按目标给出的种类选项（与各检查的基线口径对应）。
const KIND_OPTIONS: Record<string, { v: string; label: string }[]> = {
  'db-oracle': [
    { v: 'privilege', label: '权限' }, { v: 'role', label: '角色' },
    { v: 'identity', label: '身份' }, { v: 'profile', label: '概要文件项' },
  ],
  'db-mysql': [
    { v: 'privilege', label: '权限' }, { v: 'variable', label: '全局变量' }, { v: 'tls', label: '传输加密' },
  ],
  'db-sqlserver': [
    { v: 'role', label: '角色' }, { v: 'privilege', label: '权限' }, { v: 'config', label: '配置项' },
  ],
  'db-postgres': [
    { v: 'role', label: '角色' }, { v: 'role_attr', label: '角色属性' },
    { v: 'hba', label: '连接规则' }, { v: 'settings', label: '设置' },
  ],
  'os-linux': [{ v: 'sudo', label: 'sudo 授权' }, { v: 'identity', label: '身份' }],
  'os-windows': [{ v: 'identity', label: '身份' }],
  'os-hpux': [
    { v: 'identity', label: '身份' }, { v: 'service', label: '服务' },
    { v: 'setuid', label: 'setuid 文件' }, { v: 'sudo', label: 'sudo 授权' },
  ],
  'mw-tomcat': [
    { v: 'role', label: '角色' }, { v: 'deployment', label: '部署' }, { v: 'identity', label: '身份' },
  ],
  'mw-nginx': [{ v: 'identity', label: '身份' }],
  'mw-weblogic': [{ v: 'deployment', label: '部署' }, { v: 'identity', label: '身份' }],
  'mw-iis': [{ v: 'identity', label: '身份' }],
}
const kindOptions = computed(() => KIND_OPTIONS[form.value.target] ?? [
  { v: 'privilege', label: '权限' }, { v: 'role', label: '角色' }, { v: 'identity', label: '身份' },
])

const draft = ref<Allow>({ subject: '', kind: 'privilege', value: '', scope: '', reason: '' })
watch(() => form.value.target, () => {
  const opts = kindOptions.value
  if (!opts.some(k => k.v === draft.value.kind)) draft.value.kind = opts[0]?.v ?? 'privilege'
})
const draftAllows = ref<Allow[]>([])
const subjectHint = computed(() => form.value.target.startsWith('db-mysql') ? '如 root@localhost' : form.value.target === 'db-oracle' ? '如 SYS' : '如 账号/进程名')
const valueHint = computed(() => ({
  privilege: '权限名，如 SUPER', role: '角色名，如 DBA / superuser', identity: '多为账号本身，或 run-as-root',
  sudo: 'ALL', tls: 'none', profile: '如 PASSWORD_LIFE_TIME', hba: 'trust / open_network',
  role_attr: '如 CREATEROLE', deployment: '如 console / manager', service: 'inetd', setuid: 'setuid-root',
  config: '配置项名', variable: '变量名', settings: 'listen_all',
} as Record<string, string>)[draft.value.kind] ?? '放行值')

function addDraft() {
  err.value = ''
  if (!draft.value.subject || !draft.value.value) { err.value = '放行项的账号与值必填'; return }
  draftAllows.value.push({ ...draft.value })
  draft.value = { subject: '', kind: draft.value.kind, value: '', scope: '', reason: draft.value.reason }
}

async function removeAllow(b: BaselineRow, a: Allow) {
  if (!confirm(`确定从基线 ${b.id} 删除放行项「${a.subject} · ${a.kind} = ${a.value}」？之后的评估将重新计为问题。`)) return
  msg.value = ''; err.value = ''
  try {
    await api.removeBaselineAllow({ baseline_id: b.id, subject: a.subject, kind: a.kind, value: a.value, scope: a.scope })
    msg.value = `已从 ${b.id} 删除一条放行项`
    await load()
  } catch (e) { err.value = e instanceof Error ? e.message : '删除失败' }
}

// 基线 spec 的 allows 键为 Go 结构体字段名（Subject/Kind/...），大小写都兼容处理。
function allowsOf(b: BaselineRow): Allow[] {
  try {
    const spec = JSON.parse(b.spec || '{}')
    const list = (spec.allows || []) as Record<string, string>[]
    return list.map(a => ({
      subject: a.Subject ?? a.subject ?? '',
      kind: a.Kind ?? a.kind ?? '',
      value: a.Value ?? a.value ?? '',
      scope: a.Scope ?? a.scope ?? '',
      reason: a.Reason ?? a.reason ?? '',
    }))
  } catch { return [] }
}

async function load() {
  error.value = ''
  if (!hospitalId.value) { baselines.value = []; return }
  try { baselines.value = await api.baselines(hospitalId.value) }
  catch (e) { error.value = e instanceof Error ? e.message : '加载失败' }
}

async function create() {
  msg.value = ''; err.value = ''
  let allows: unknown[]
  if (form.value.allowsText.trim()) {
    try { allows = JSON.parse(form.value.allowsText) }
    catch { err.value = 'allows 不是合法 JSON'; return }
  } else {
    allows = draftAllows.value
  }
  if (!allows.length) { err.value = '至少添加一条放行项（或用高级 JSON）'; return }
  if (!form.value.id) { err.value = '基线 ID 必填'; return }
  try {
    await api.createBaseline({
      id: form.value.id, hospital_id: form.value.hospital_id,
      target: form.value.target, allows, created_by: form.value.created_by,
    })
    msg.value = `基线 ${form.value.id} 已创建`
    draftAllows.value = []
    hospitalId.value = form.value.hospital_id
    await load()
  } catch (e) { err.value = e instanceof Error ? e.message : '创建失败' }
}

// 编辑：只改放行项，ID/医院/目标锁定；保存整体替换，版本 +1。
const editingId = ref('')
function startEdit(b: BaselineRow) {
  msg.value = ''; err.value = ''
  editingId.value = b.id
  form.value.id = b.id
  form.value.hospital_id = b.hospital_id
  form.value.target = b.target
  form.value.allowsText = ''
  draftAllows.value = allowsOf(b).map(a => ({ ...a }))
  const opts = KIND_OPTIONS[b.target] ?? []
  draft.value = { subject: '', kind: opts[0]?.v ?? 'privilege', value: '', scope: '', reason: draft.value.reason }
  window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' })
}
function cancelEdit() {
  editingId.value = ''
  form.value.id = ''
  form.value.allowsText = ''
  form.value.target = 'db-mysql'
  form.value.hospital_id = hospitalId.value
  draftAllows.value = []
  draft.value = { subject: '', kind: 'privilege', value: '', scope: '', reason: draft.value.reason }
  msg.value = ''; err.value = ''
}
async function saveEdit() {
  msg.value = ''; err.value = ''
  let allows: unknown[]
  if (form.value.allowsText.trim()) {
    try { allows = JSON.parse(form.value.allowsText) }
    catch { err.value = 'allows 不是合法 JSON'; return }
  } else {
    allows = draftAllows.value
  }
  if (!allows.length) { err.value = '至少保留一条放行项（要整条去掉请用删除）'; return }
  try {
    await api.updateBaseline(editingId.value, allows)
    msg.value = `基线 ${editingId.value} 已修改（版本 +1）`
    cancelEdit()
    await load()
  } catch (e) { err.value = e instanceof Error ? e.message : '修改失败' }
}
async function deleteBaselineRow(b: BaselineRow) {
  if (!confirm(`确定删除整条基线 ${b.id}？已存的问题与报告不动，之后的评估不再用它豁免。`)) return
  msg.value = ''; err.value = ''
  try {
    await api.deleteBaseline(b.id)
    if (editingId.value === b.id) cancelEdit()
    msg.value = `基线 ${b.id} 已删除`
    await load()
  } catch (e) { err.value = e instanceof Error ? e.message : '删除失败' }
}

onMounted(async () => {
  try {
    hospitals.value = await api.hospitals()
    const site = await loadSite()
    const pick = (selectedHospital.id && hospitals.value.some(h => h.id === selectedHospital.id))
      ? selectedHospital.id
      : (site.hospital_id && hospitals.value.some(h => h.id === site.hospital_id))
        ? site.hospital_id
        : hospitals.value[0]?.id ?? ''
    if (pick) {
      hospitalId.value = pick
      form.value.hospital_id = pick
    }
    await load()
  } catch (e) { error.value = e instanceof Error ? e.message : '加载失败' }
})
</script>
