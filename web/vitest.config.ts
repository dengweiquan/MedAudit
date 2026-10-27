import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

// 单元测试只跑 src 下的 *.test.ts；e2e/smoke.spec.ts 归 Playwright
//（npm run test:e2e），vitest 收它会因缺少 Playwright 夹具而失败。
export default defineConfig({
  plugins: [vue()],
  test: {
    include: ['src/**/*.test.ts'],
  },
})
