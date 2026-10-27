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
      <span class="todo" v-if="hospitalLabel" style="margin-left:12px">当前医院：{{ hospitalLabel }} <button class="btn small" :disabled="mustChange" @click="goto('admin')">管理页切换</button></span>
      <label class="userbox" style="gap:4px" title="工程师模式只切换界面显示，不是权限控制；现在所有账号权限相同。">
        <input type="checkbox" :checked="engineerMode.on" @change="toggleEngineer(($event.target as HTMLInputElement).checked)" />
        工程师模式
      </label>
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
      <button v-for="t in tabs" :key="t.key" :class="{ active: nav.view === t.key || (t.key === 'objects' && ['databases', 'os', 'middleware', 'api'].includes(nav.view)) }" @click="goto(t.key)">
        {{ t.label }}
      </button>
    </nav>

    <DashboardView v-if="nav.view === 'dashboard'" />
    <!-- 旧类别路由（数据库/操作系统/中间件/业务接口）保留并跳转到审计对象页对应筛选（M37-2.2）。 -->
    <ObjectsView v-else-if="nav.view === 'objects' || nav.view === 'databases' || nav.view === 'os' || nav.view === 'middleware' || nav.view === 'api'" />
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
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { api, type Health, type Hospital } from './api'
import { nav, goto, selectedHospital, setHospital, engineerMode, setEngineerMode } from './store'
import { loadSite } from './util'
import LoginView from './views/LoginView.vue'
import SiteFooter from './components/SiteFooter.vue'
import DashboardView from './views/DashboardView.vue'
import BundlesView from './views/BundlesView.vue'
import FindingsView from './views/FindingsView.vue'
import ReportsView from './views/ReportsView.vue'
import BaselinesView from './views/BaselinesView.vue'
import RulesView from './views/RulesView.vue'
import PathsView from './views/PathsView.vue'
import RecheckView from './views/RecheckView.vue'
import AdminView from './views/AdminView.vue'
import ObjectsView from './views/ObjectsView.vue'

// 医院模式（默认）5 个菜单；工程师模式额外显示 5 个。
// 只是界面显示切换，不是权限控制。
const hospitalTabs = [
  { key: 'dashboard', label: '首页' },
  { key: 'objects', label: '审计对象' },
  { key: 'findings', label: '问题' },
  { key: 'reports', label: '报告' },
  { key: 'recheck', label: '复检对比' },
]
const engineerTabs = [
  { key: 'bundles', label: '审计记录' },
  { key: 'baselines', label: '基线' },
  { key: 'rules', label: '规则' },
  { key: 'paths', label: '关联分析' },
  { key: 'admin', label: '管理' },
]
const tabs = computed(() => engineerMode.on ? [...hospitalTabs, ...engineerTabs] : hospitalTabs)
const engineerOnly = new Set(engineerTabs.map(t => t.key))
function toggleEngineer(on: boolean) {
  setEngineerMode(on)
  // 切回医院模式时，若正停在工程师专属页，回到首页，避免空白页。
  if (!on && engineerOnly.has(nav.view)) goto('dashboard')
}

// M12 鉴权态：checking → in / out；任一 API 返回 401 时自动回登录页
const authState = ref<'checking' | 'in' | 'out'>('checking')
const username = ref('')
const health = ref<Health | null>(null)

// 顶栏当前医院指示（只显示、不在这里选，切换去管理页）。
// selectedHospital 是 reactive，管理页改动后各页重挂载时读到新值；
// 顶栏本身需在登录后校验一次：单院锁定本站，已删医院的残留选择清回全部。
const hospitals = ref<Hospital[]>([])
const hospitalLabel = computed(() => {
  if (!selectedHospital.id) return '全部医院'
  const h = hospitals.value.find(x => x.id === selectedHospital.id)
  return h ? `${h.id}（${h.name}）` : selectedHospital.id
})
async function resolveHospital() {
  try {
    hospitals.value = await api.hospitals()
    const site = await loadSite()
    if (site.hospital_id) { setHospital(site.hospital_id); return }
    if (selectedHospital.id && !hospitals.value.some(h => h.id === selectedHospital.id)) setHospital('')
  } catch { /* 医院列表取不到时保留当前选择，不挡登录 */ }
}

function onLogin(user: string) {
  username.value = user
  authState.value = 'in'
  void refreshHealth()
  void checkMustChange()
  void resolveHospital()
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
    await resolveHospital()
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
