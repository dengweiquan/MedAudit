<template>
  <div class="login-wrap">
    <div class="card login-card">
      <h1>MedAudit 医疗权限核查平台</h1>
      <p class="sub">请登录后继续</p>
      <p class="mode-switch">
        <button type="button" class="btn small" :class="{ primary: mode === 'password' }" @click="mode = 'password'">口令登录</button>
        <button type="button" class="btn small" :class="{ primary: mode === 'token' }" @click="mode = 'token'">令牌登录</button>
      </p>
      <form @submit.prevent="submit">
        <template v-if="mode === 'password'">
          <label>用户名
            <input v-model="username" autocomplete="username" required :disabled="busy" />
          </label>
          <label>口令
            <input v-model="password" type="password" autocomplete="current-password" required :disabled="busy" />
          </label>
        </template>
        <template v-else>
          <label>超级令牌
            <input v-model="token" type="password" autocomplete="off" required :disabled="busy" />
          </label>
          <p class="sub">令牌由工程师经 ma token 生成，重启后仍然有效；用户名密码仍可正常登录。</p>
        </template>
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
const mode = ref<'password' | 'token'>('password')
const username = ref('admin')
const password = ref('')
const token = ref('')
const error = ref('')
const busy = ref(false)

async function submit() {
  error.value = ''
  busy.value = true
  try {
    const res = mode.value === 'token'
      ? await api.loginToken(token.value)
      : await api.login(username.value.trim(), password.value)
    password.value = ''
    token.value = ''
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
