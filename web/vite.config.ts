import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// M0：构建产物由 medaudit-server 直接 serve；dev 时代理 API 到本地 server。
export default defineConfig({
  plugins: [vue()],
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8080',
    },
  },
})
