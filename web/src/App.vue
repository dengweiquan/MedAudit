<template>
  <LoginView v-if="authState === 'out'" @success="onLogin" />
  <p class="empty" v-else-if="authState === 'checking'">加载中…</p>

  <template v-else>
    <header>
      <div class="logo">M</div>
      <div>
        <h1>MedAudit 医疗权限核查平台</h1>
        <div class="subtitle">数据库 · 操作系统 · 中间件 · 业务接口</div>
      </div>
      <span class="badge" v-if="health"><span class="dot"></span>运行正常<span class="ver">{{ health.version }}</span></span>
      <span class="badge off" v-else><span class="dot"></span>连接中…</span>
      <span class="userbox">
        <span class="user-name">{{ username }}</span>
        <button class="btn small" :disabled="mustChange" @click="showPw = !showPw">修改口令</button>
        <button class="btn small" @click="doLogout">退出</button>
      </span>
    </header>

    <div class="card" v-if="showPw">
      <h2>修改口令</h2>
      <p class="msg err" v-if="mustChange">当前口令为初始/重置口令，须先修改后才能继续使用平台。</p>
      <form class="inline-form" @submit.prevent="doChangePw">
        <input v-model="pwOld" type="password" placeholder="当前口令" autocomplete="current-password" required />
        <input v-model="pwNew" type="password" placeholder="新口令（至少 8 位）" autocomplete="new-password" required />
        <input v-model="pwNew2" type="password" placeholder="再次输入新口令" autocomplete="new-password" required />
        <button class="btn primary" type="submit" :disabled="pwBusy">提交</button>
      </form>
      <p class="msg" v-if="pwMsg">{{ pwMsg }}</p>
      <p class="msg err" v-if="pwErr">{{ pwErr }}</p>
    </div>

    <template v-if="!mustChange">
    <nav class="tabs">
      <button v-for="t in tabs" :key="t.key" :class="{ active: nav.view === t.key }" @click="goto(t.key)">
        {{ t.label }}
      </button>
    </nav>

    <DashboardView v-if="nav.view === 'dashboard'" />
    <DatabasesView v-else-if="nav.view === 'databases'" />
    <OsView v-else-if="nav.view === 'os'" />
    <MiddlewareView v-else-if="nav.view === 'middleware'" />
    <ApiView v-else-if="nav.view === 'api'" />
    <BundlesView v-else-if="nav.view === 'bundles'" />
    <FindingsView v-else-if="nav.view === 'findings'" />
    <ReportsView v-else-if="nav.view === 'reports'" />
    <RecheckView v-else-if="nav.view === 'recheck'" />
    <BaselinesView v-else-if="nav.view === 'baselines'" />
    <RulesView v-else-if="nav.view === 'rules'" />
    <PathsView v-else-if="nav.view === 'paths'" />
    <AdminView v-else-if="nav.view === 'admin'" />
    </template>
    <SiteFooter />
  </template>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { api, type Health } from './api'
import { nav, goto } from './store'
import LoginView from './views/LoginView.vue'
import SiteFooter from './components/SiteFooter.vue'
import DashboardView from './views/DashboardView.vue'
import DatabasesView from './views/DatabasesView.vue'
import OsView from './views/OsView.vue'
import MiddlewareView from './views/MiddlewareView.vue'
import ApiView from './views/ApiView.vue'
import BundlesView from './views/BundlesView.vue'
import FindingsView from './views/FindingsView.vue'
import ReportsView from './views/ReportsView.vue'
import BaselinesView from './views/BaselinesView.vue'
import RulesView from './views/RulesView.vue'
import PathsView from './views/PathsView.vue'
import RecheckView from './views/RecheckView.vue'
import AdminView from './views/AdminView.vue'

const tabs = [
  { key: 'dashboard', label: '工作台' },
  { key: 'databases', label: '数据库' },
  { key: 'os', label: '操作系统' },
  { key: 'middleware', label: '中间件' },
  { key: 'api', label: '业务接口' },
  { key: 'bundles', label: '审计记录' },
  { key: 'findings', label: '问题' },
  { key: 'reports', label: '报告' },
  { key: 'recheck', label: '复检对比' },
  { key: 'baselines', label: '基线' },
  { key: 'rules', label: '规则' },
  { key: 'paths', label: '关联分析' },
  { key: 'admin', label: '管理' },
]

// M12 鉴权态：checking → in / out；任一 API 返回 401 时自动回登录页
const authState = ref<'checking' | 'in' | 'out'>('checking')
const username = ref('')
const health = ref<Health | null>(null)

function onLogin(user: string) {
  username.value = user
  authState.value = 'in'
  void refreshHealth()
  void checkMustChange()
}

// M20：must_change_pwd 时强制先改密（挡住导航与全部视图）
const mustChange = ref(false)
async function checkMustChange() {
  try {
    const me = await api.me()
    mustChange.value = !!me.must_change_pwd
    if (mustChange.value) showPw.value = true
  } catch { /* 忽略：未登录态由主流程处理 */ }
}
function onUnauthorized() {
  if (authState.value === 'in') authState.value = 'out'
}
async function doLogout() {
  try { await api.logout() } catch { /* 会话已失效也照常退出 */ }
  username.value = ''
  showPw.value = false
  authState.value = 'out'
}
async function refreshHealth() {
  try { health.value = await api.health() } catch { health.value = null }
}

// 修改口令
const showPw = ref(false)
const pwOld = ref('')
const pwNew = ref('')
const pwNew2 = ref('')
const pwMsg = ref('')
const pwErr = ref('')
const pwBusy = ref(false)
async function doChangePw() {
  pwMsg.value = ''
  pwErr.value = ''
  if (pwNew.value !== pwNew2.value) { pwErr.value = '两次输入的新口令不一致'; return }
  pwBusy.value = true
  try {
    await api.changePassword(pwOld.value, pwNew.value)
    pwMsg.value = '口令已修改'
    pwOld.value = pwNew.value = pwNew2.value = ''
    if (mustChange.value) { mustChange.value = false; showPw.value = false }
  } catch (e) {
    pwErr.value = e instanceof Error ? e.message : '修改失败'
  } finally {
    pwBusy.value = false
  }
}

onMounted(async () => {
  window.addEventListener('medaudit:unauthorized', onUnauthorized)
  await refreshHealth()
  try {
    const me = await api.me()
    username.value = me.username
    authState.value = 'in'
    mustChange.value = !!me.must_change_pwd
    if (mustChange.value) showPw.value = true
  } catch {
    authState.value = 'out'
  }
})
onUnmounted(() => window.removeEventListener('medaudit:unauthorized', onUnauthorized))
</script>

<style scoped>
.userbox { margin-left: auto; display: flex; gap: 8px; align-items: center; }
.user-name { font-size: 13px; color: #444; }
</style>
