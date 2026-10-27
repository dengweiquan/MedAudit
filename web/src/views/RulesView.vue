<template>
  <div class="card">
    <h2>规则集（{{ rules.length }} 条，已关闭 {{ disabledCount }} 条）</h2>
    <p class="todo">
      工程师可关闭本站不适用的检查项（如客户现场 Oracle SYS/SYSTEM 为厂商必需账号，必须保持开启）：
      关闭后该项在评估时整体跳过——不产生问题、报告不体现。关闭必须填写原因，操作留痕。
      注意与基线的分工：基线豁免单个主体，启停关闭整项检查。
    </p>
    <div class="todo" v-if="frameworks.length" style="margin-bottom:8px">
      报告中的合规逐条判定：
      <span v-for="(f, i) in frameworks" :key="f.id">{{ i ? '；' : '' }}{{ f.name }}（{{ f.clauses }} 条，{{ f.status === 'verified' ? '已核实' : '草稿' }}，<b>{{ f.enabled ? '已启用' : '未启用' }}</b>）</span>
    </div>
    <div class="chips">
      <button class="chip" :class="{ active: target === '' }" @click="target = ''">全部</button>
      <button v-for="t in targets" :key="t" class="chip" :class="{ active: target === t }" @click="target = t">{{ t }}</button>
    </div>
    <div class="inline-form" v-if="selected.size" style="margin:8px 0">
      <span>已选 {{ selected.size }} 条</span>
      <input v-model="batchReason" placeholder="批量关闭原因（批量开启可空）" style="min-width:260px" />
      <button class="btn small" @click="batch(false)">批量关闭</button>
      <button class="btn small primary" @click="batch(true)">批量开启</button>
      <button class="btn small" @click="selected.clear()">清空选择</button>
    </div>
    <div class="msg" v-if="msg">{{ msg }}</div>
    <div class="msg err" v-if="opErr">{{ opErr }}</div>
    <div v-if="error" class="error">{{ error }}</div>
    <table v-else-if="shown.length">
      <thead><tr><th></th><th>规则 ID</th><th>名称</th><th>目标</th><th>风险</th><th>状态</th><th>说明 / 整改建议</th><th>操作</th></tr></thead>
      <tbody>
        <tr v-for="r in shown" :key="r.ID" :style="isOff(r.ID) ? 'opacity:.55' : ''">
          <td><input type="checkbox" :checked="selected.has(r.ID)" @change="toggleSel(r.ID)" /></td>
          <td><code>{{ r.ID }}</code></td>
          <td>{{ r.Name }}</td>
          <td>{{ r.Target }}</td>
          <td><span class="concl" :class="'risk-' + r.Risk">{{ r.Risk }}</span></td>
          <td>
            <span v-if="isOff(r.ID)" class="concl c-FAIL">已关闭</span>
            <span v-else class="concl c-PASS">启用</span>
            <div v-if="isOff(r.ID)" class="todo">{{ toggleOf(r.ID)?.reason }}（{{ toggleOf(r.ID)?.updated_by }} · {{ fmtLocal(toggleOf(r.ID)?.updated_at) }}）</div>
          </td>
          <td style="font-size:13px">{{ r.Description }}<div class="todo">整改：{{ r.Remediation }}</div>
            <div class="todo" v-if="r.Compliance?.length">等保条款：<span v-for="(c, i) in r.Compliance" :key="c.id" :title="c.title">{{ i ? '；' : '' }}{{ c.id }} {{ c.group }}</span></div></td>
          <td>
            <button v-if="!isOff(r.ID)" class="btn small" @click="askOff(r.ID)">关闭</button>
            <button v-else class="btn small primary" @click="setOne(r.ID, true)">开启</button>
          </td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty">暂无规则。</div>

    <div class="card" v-if="offTarget" style="margin-top:12px">
      <h3>关闭检查项：{{ offTarget }}</h3>
      <div class="inline-form">
        <input v-model="offReason" placeholder="关闭原因（必填，如：现场 SYS/SYSTEM 为厂商必需账号）" style="min-width:340px" />
        <input v-model="offBy" placeholder="操作人" />
        <button class="btn primary" :disabled="!offReason" @click="confirmOff">确认关闭</button>
        <button class="btn" @click="offTarget = ''">取消</button>
      </div>
      <p class="todo">关闭后新评估不再执行该项；已生成的历史报告为快照，不受影响。</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { api, type Rule, type RuleToggle } from '../api'
import { fmtLocal } from '../util'
import { reviewerName } from '../store'

const rules = ref<Rule[]>([])
const frameworks = ref<{ id: string; name: string; status: string; clauses: number; enabled: boolean }[]>([])
api.complianceFrameworks().then(r => { frameworks.value = r.items }).catch(() => { frameworks.value = [] })
const toggles = ref<Map<string, RuleToggle>>(new Map())
const target = ref('')
const error = ref('')
const msg = ref('')
const opErr = ref('')
const selected = reactive(new Set<string>())
const batchReason = ref('')
const offTarget = ref('')
const offReason = ref('')
const offBy = ref(reviewerName())

const targets = computed(() => [...new Set(rules.value.map(r => r.Target))])
const shown = computed(() => target.value ? rules.value.filter(r => r.Target === target.value) : rules.value)
const disabledCount = computed(() => [...toggles.value.values()].filter(t => !t.enabled).length)

function toggleOf(id: string): RuleToggle | undefined { return toggles.value.get(id) }
function isOff(id: string): boolean { return toggles.value.get(id)?.enabled === false }
function toggleSel(id: string) { selected.has(id) ? selected.delete(id) : selected.add(id) }

async function load() {
  rules.value = await api.rules()
  const list = await api.ruleToggles()
  toggles.value = new Map(list.map(t => [t.rule_id, t]))
}

async function setOne(id: string, enabled: boolean, reason?: string) {
  opErr.value = ''; msg.value = ''
  try {
    await api.setRuleToggle({ rule_id: id, enabled, reason: reason ?? '', updated_by: offBy.value || reviewerName() })
    msg.value = `${id} 已${enabled ? '开启' : '关闭'}`
    await load()
  } catch (e) { opErr.value = e instanceof Error ? e.message : '操作失败' }
}

function askOff(id: string) {
  offTarget.value = id
  offReason.value = ''
  opErr.value = ''
}
async function confirmOff() {
  const id = offTarget.value
  await setOne(id, false, offReason.value)
  if (!opErr.value) offTarget.value = ''
}

async function batch(enabled: boolean) {
  opErr.value = ''; msg.value = ''
  if (!enabled && !batchReason.value) { opErr.value = '批量关闭必须填写原因'; return }
  const ids = [...selected]
  let ok = 0
  for (const id of ids) {
    try {
      await api.setRuleToggle({ rule_id: id, enabled, reason: enabled ? '' : batchReason.value, updated_by: offBy.value || reviewerName() })
      ok++
    } catch (e) { opErr.value = e instanceof Error ? e.message : '操作失败' }
  }
  msg.value = `批量${enabled ? '开启' : '关闭'}完成：${ok}/${ids.length} 条`
  selected.clear()
  batchReason.value = ''
  await load()
}

onMounted(async () => {
  try { await load() }
  catch (e) { error.value = e instanceof Error ? e.message : '加载失败' }
})
</script>
