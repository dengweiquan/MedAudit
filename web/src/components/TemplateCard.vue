<template>
  <div class="card">
    <h2>从模板套用基线</h2>
    <p class="todo" style="margin:4px 0 10px">实施时先套用：内置账号模板可直接用；HIS/LIS/PACS 厂商模板是常见做法整理（标「草稿」），套用前把 {…} 换成现场实际账号，不需要的条目取消勾选，并请厂商出具书面说明留档。</p>
    <div class="chips">
      <button v-for="t in templates" :key="t.id" class="chip" :class="{ active: cur?.id === t.id }" @click="pick(t)">
        {{ t.system }} · {{ t.name }}<span v-if="t.status === 'draft'"> · 草稿</span>
      </button>
    </div>
    <div v-if="cur" style="margin-top:10px">
      <div class="todo" style="white-space:pre-line">{{ cur.description }}</div>
      <div class="form-grid" v-if="cur.placeholders.length" style="margin-top:8px">
        <label v-for="p in cur.placeholders" :key="p">{{ p }}<input v-model="values[p]" placeholder="现场实际账号" /></label>
      </div>
      <table style="margin-top:8px">
        <thead><tr><th></th><th>账号</th><th>放行内容</th><th>理由</th></tr></thead>
        <tbody>
          <tr v-for="(e, i) in cur.entries" :key="i" :style="skip.has(i) ? 'opacity:.5' : ''">
            <td><input type="checkbox" :checked="!skip.has(i)" @change="toggle(i)" /></td>
            <td>{{ fill(e.subject) }}</td>
            <td>{{ baselineKindLabel(e.kind) }} = {{ e.value }}<span v-if="e.scope" class="todo"> · {{ e.scope }}</span></td>
            <td class="todo">{{ e.reason }}</td>
          </tr>
        </tbody>
      </table>
      <div class="inline-form" style="margin-top:8px">
        <label>写入基线<input v-model="baselineId" placeholder="bl-..." /></label>
        <button class="btn primary" :disabled="!hospitalId || applying" @click="apply">一键套用</button>
        <span class="todo">已有同名基线则追加，没有则新建；套用后自动重评本院同类对象的最新审计。</span>
      </div>
    </div>
    <div class="msg" v-if="msg">{{ msg }}</div>
    <div class="msg err" v-if="err">{{ err }}</div>
    <div class="msg err" v-for="e in loadErrors" :key="e">模板文件有误：{{ e }}</div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { api, type BaselineTemplate } from '../api'
import { baselineKindLabel } from '../util'

const props = defineProps<{ hospitalId: string }>()
const emit = defineEmits<{ applied: [] }>()

const templates = ref<BaselineTemplate[]>([])
const loadErrors = ref<string[]>([])
const cur = ref<BaselineTemplate | null>(null)
const values = reactive<Record<string, string>>({})
const skip = ref(new Set<number>())
const baselineId = ref('')
const applying = ref(false)
const msg = ref('')
const err = ref('')

function pick(t: BaselineTemplate) {
  cur.value = t
  skip.value = new Set()
  for (const k of Object.keys(values)) delete values[k]
  baselineId.value = 'bl-' + t.id
  msg.value = ''; err.value = ''
}

function toggle(i: number) {
  const s = new Set(skip.value)
  if (s.has(i)) s.delete(i); else s.add(i)
  skip.value = s
}

function fill(subject: string): string {
  return subject.replace(/\{[^{}]+\}/g, p => values[p]?.trim() || p)
}

async function apply() {
  if (!cur.value) return
  applying.value = true; msg.value = ''; err.value = ''
  try {
    const r = await api.applyBaselineTemplate(cur.value.id, {
      hospital_id: props.hospitalId, baseline_id: baselineId.value.trim(),
      values: { ...values }, skip: [...skip.value],
    })
    msg.value = `${r.created ? '已新建' : '已追加到'}基线 ${r.baseline_id}：新增 ${r.added} 条放行项，已重评 ${r.reevaluated} 个对象的最新审计。`
    if (r.reevaluate_error) err.value = r.reevaluate_error
    emit('applied')
  } catch (e) {
    err.value = e instanceof Error ? e.message : String(e)
  } finally {
    applying.value = false
  }
}

onMounted(async () => {
  try {
    const r = await api.baselineTemplates()
    templates.value = r.items
    loadErrors.value = r.errors
  } catch (e) {
    err.value = e instanceof Error ? e.message : String(e)
  }
})
</script>
