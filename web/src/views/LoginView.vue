<template>
  <div class="login-wrap">
    <div class="card login-card">
      <h1>MedAudit 医疗权限核查平台</h1>
      <p class="sub">请登录后继续</p>
      <form @submit.prevent="submit">
        <label>用户名
          <input v-model="username" autocomplete="username" required :disabled="busy" />
        </label>
        <label>口令
          <input v-model="password" type="password" autocomplete="current-password" required :disabled="busy" />
        </label>
        <p class="msg err" v-if="error">{{ error }}</p>
        <button class="btn primary login-btn" type="submit" :disabled="busy">
          {{ busy ? '登录中…' : '登录' }}
        </button>
      </form>
    </div>
    <SiteFooter class="login-footer" />
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { api } from '../api'
import SiteFooter from '../components/SiteFooter.vue'

const emit = defineEmits<{ success: [username: string] }>()
const username = ref('admin')
const password = ref('')
const error = ref('')
const busy = ref(false)

async function submit() {
  error.value = ''
  busy.value = true
  try {
    const res = await api.login(username.value.trim(), password.value)
    password.value = ''
    emit('success', res.username)
  } catch (e) {
    error.value = e instanceof Error ? e.message : '登录失败'
  } finally {
    busy.value = false
  }
}
</script>

<style scoped>
.login-wrap { display: flex; flex-direction: column; align-items: center; padding-top: 10vh; }
.login-footer { width: 340px; }
.login-card { width: 340px; padding: 28px 30px; }
.login-card h1 { font-size: 19px; margin: 0 0 4px; }
.login-card .sub { color: #666; font-size: 13px; margin: 0 0 18px; }
.login-card label { display: flex; flex-direction: column; gap: 5px; font-size: 13px; color: #444; margin-bottom: 12px; }
.login-btn { width: 100%; padding: 8px 0; font-size: 14px; margin-top: 4px; }
</style>
