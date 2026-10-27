<template>
  <div class="card" v-if="asset && rc">
    <h2>远程审计：{{ asset.name }}（{{ asset.id }}）</h2>
    <p class="todo">
      将经 {{ rc.transport === 'winrm' ? 'WinRM' : 'SSH' }} 把采集器推送到 {{ rc.host }}，
      以账号 {{ rc.user }} 在目标机真实执行采集，随后自动评估并生成报告。
      口令仅本次使用，不保存。{{ rc.transport === 'winrm' ? 'Windows 目标机将从登记的服务地址拉取采集器程序。' : '' }}
    </p>
    <div class="inline-form">
      <input v-model="form.password" type="password" placeholder="登录口令" autocomplete="off" style="min-width:220px" />
      <label>基线
        <select v-model="form.baseline_id">
          <option value="">无基线</option>
          <option v-for="b in baselines" :key="b.id" :value="b.id">{{ b.id }}</option>
        </select>
      </label>
      <input v-model="form.created_by" placeholder="审计人" />
      <button class="btn primary" :disabled="running || !form.password" @click="run">开始审计</button>
      <button class="btn" :disabled="running" @click="emit('close')">关闭</button>
    </div>
    <div v-if="running" class="todo">远程审计中…推送与采集可能需要数分钟，请勿关闭页面。</div>
    <div class="msg err" v-if="err">{{ err }}</div>
    <div v-if="result">
      <p>
        审计完成（传输：{{ result.transport }}<span v-if="result.host_key_fingerprint">，主机密钥 {{ result.host_key_fingerprint }}</span>）：
        采集事实 {{ result.facts }} 条 / 收据 {{ result.receipts }} 张；
        评估 {{ result.evaluation.total }} 条结果，不通过 {{ result.evaluation.fail }} 项，问题落库 {{ result.evaluation.findings_stored }}。
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
import { computed, ref, watch } from 'vue'
import { api, parseRemote, type Asset, type BaselineRow, type RemoteAuditResult } from '../api'
import { goto } from '../store'

const props = defineProps<{ asset: Asset | null }>()
const emit = defineEmits<{ close: []; done: [] }>()

const rc = computed(() => (props.asset ? parseRemote(props.asset) : null))
const form = ref({ password: '', baseline_id: '', created_by: '' })
const baselines = ref<BaselineRow[]>([])
const running = ref(false)
const err = ref('')
const result = ref<RemoteAuditResult | null>(null)

watch(() => props.asset, async (a) => {
  form.value = { password: '', baseline_id: '', created_by: '' }
  err.value = ''
  result.value = null
  baselines.value = []
  if (a) {
    try { baselines.value = await api.baselines(a.hospital_id) } catch { /* 无基线可选不阻塞 */ }
  }
})

async function run() {
  if (!props.asset) return
  running.value = true
  err.value = ''
  result.value = null
  try {
    result.value = await api.runRemoteAudit({
      asset_id: props.asset.id,
      password: form.value.password,
      baseline_id: form.value.baseline_id || undefined,
      created_by: form.value.created_by || undefined,
    })
    form.value.password = ''
    emit('done')
  } catch (e) {
    err.value = e instanceof Error ? e.message : '远程审计失败'
  } finally {
    running.value = false
  }
}
</script>
