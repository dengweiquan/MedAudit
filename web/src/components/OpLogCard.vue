<template>
  <div class="card">
    <h2>操作日志（{{ total }}）</h2>
    <div class="inline-form" style="margin-bottom:8px">
      <button class="btn" @click="verify">校验日志完整性</button>
      <span class="msg" v-if="check && check.ok">完整：{{ check.rows }} 条记录未被改动</span>
      <span class="msg err" v-if="check && !check.ok">日志被改动：第 {{ check.broken_at }} 条起记录不可信</span>
      <span class="msg err" v-if="err">{{ err }}</span>
    </div>
    <table v-if="items.length">
      <thead><tr><th>时间</th><th>操作人</th><th>操作</th><th>结果</th><th>来源 IP</th></tr></thead>
      <tbody>
        <tr v-for="e in items" :key="e.id">
          <td>{{ fmtLocal(e.at) }}</td>
          <td>{{ e.actor }}</td>
          <td :title="e.method + ' ' + e.path">{{ actionLabel(e) }}</td>
          <td><span class="concl" :class="e.status < 400 ? 'c-PASS' : 'c-FAIL'">{{ e.status < 400 ? '成功' : '失败' }}</span></td>
          <td>{{ e.client_ip }}</td>
        </tr>
      </tbody>
    </table>
    <div class="inline-form" v-if="total > PAGE" style="margin-top:8px">
      <button class="btn small" :disabled="offset === 0" @click="go(offset - PAGE)">上一页</button>
      <span>{{ offset + 1 }}–{{ Math.min(offset + PAGE, total) }} / {{ total }}</span>
      <button class="btn small" :disabled="offset + PAGE >= total" @click="go(offset + PAGE)">下一页</button>
    </div>
    <div class="todo">记录平台上的所有改动与文件下载（谁、何时、做了什么、是否成功），不记录口令。日志逐条串联校验，任何一条被改或被删都能查出来；一键清场不会清除操作日志。</div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, type OpLogRow } from '../api'
import { fmtLocal } from '../util'

const PAGE = 50
const items = ref<OpLogRow[]>([])
const total = ref(0)
const offset = ref(0)
const err = ref('')
const check = ref<{ ok: boolean; rows: number; broken_at: number } | null>(null)

// 路径前缀 → 通俗说明；未列出的显示原始请求。
const LABELS: [string, string, string][] = [
  ['POST', '/api/v1/auth/login', '登录'],
  ['POST', '/api/v1/auth/logout', '退出登录'],
  ['POST', '/api/v1/auth/change-password', '修改口令'],
  ['POST', '/api/v1/auth/token/disable', '停用超级令牌'],
  ['POST', '/api/v1/auth/token', '生成超级令牌'],
  ['POST', '/api/v1/admin/wipe', '一键清场'],
  ['GET', '/api/v1/admin/backup', '下载平台备份'],
  ['POST', '/api/v1/audit/run-remote', '远程审计'],
  ['POST', '/api/v1/audit/run', '开始审计'],
  ['POST', '/api/v1/bundles', '导入事实包'],
  ['GET', '/api/v1/bundles/', '下载证据'],
  ['GET', '/api/v1/reports/', '导出报告'],
  ['GET', '/api/v1/api-audits/', '导出接口审计报告'],
  ['GET', '/api/v1/agent/download', '下载采集器'],
  ['POST', '/api/v1/baselines/exempt-preview', '预览加入基线'],
  ['POST', '/api/v1/baselines/exempt', '加入基线'],
  ['POST', '/api/v1/baselines/remove-allow', '移出基线条目'],
  ['', '/api/v1/baselines', '修改基线'],
  ['', '/api/v1/rule-toggles', '规则启停'],
  ['', '/api/v1/users', '用户管理'],
  ['', '/api/v1/assets', '资产登记/修改'],
  ['', '/api/v1/hospitals', '医院登记/修改'],
  ['', '/api/v1/findings', '问题复核'],
  ['', '/api/v1/evaluations', '重新评估'],
  ['', '/api/v1/reports', '生成报告'],
  ['', '/api/v1/correlations', '关联分析'],
  ['', '/api/v1/api-audits', '接口审计'],
]

function actionLabel(e: OpLogRow): string {
  for (const [m, p, label] of LABELS) {
    if ((m === '' || m === e.method) && e.path.startsWith(p)) {
      if (e.method === 'DELETE') return label + '（删除）'
      return e.note ? `${label}（${e.note}）` : label
    }
  }
  return `${e.method} ${e.path}`
}

async function go(o: number) {
  err.value = ''
  try {
    const r = await api.opLog(o, PAGE)
    items.value = r.items
    total.value = r.total
    offset.value = o
  } catch (e: any) {
    err.value = e.message || String(e)
  }
}

async function verify() {
  err.value = ''
  try {
    check.value = await api.verifyOpLog()
  } catch (e: any) {
    err.value = e.message || String(e)
  }
}

onMounted(() => go(0))
</script>
