import { defineConfig } from '@playwright/test'

// M37-2.9 医院模式冒烟：跑法见 e2e/smoke.spec.ts 头注。
// 环境变量：
//   E2E_BASE_URL            服务地址，默认 http://127.0.0.1:8080
//   E2E_ADMIN_USER          默认 admin
//   E2E_ADMIN_PASSWORD      默认 Stage@123456（演示/staging 口令，不是生产口令）
//   E2E_PROXY_SERVER        需经隧道代理访问服务时设，如 http://hatch-egress-proxy:3130
//   E2E_PROXY_USERNAME / E2E_PROXY_PASSWORD（与代理认证对应；不写进文件）
//   E2E_CHROMIUM_EXECUTABLE_PATH  本地无 Playwright 浏览器时指向已装的 Chromium
export default defineConfig({
  testDir: './e2e',
  // 单条冒烟用例走完全部页面 + 复检服务端重算 + 末尾 reload，隧道下实测 45–60 秒，
  // 60 秒时限已多次在最后一步超时（非产品回归），放宽到 120 秒。
  timeout: 120_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://127.0.0.1:8080',
    viewport: { width: 1366, height: 900 },
    proxy: process.env.E2E_PROXY_SERVER
      ? {
          server: process.env.E2E_PROXY_SERVER,
          username: process.env.E2E_PROXY_USERNAME,
          password: process.env.E2E_PROXY_PASSWORD,
        }
      : undefined,
    launchOptions: process.env.E2E_CHROMIUM_EXECUTABLE_PATH
      ? { executablePath: process.env.E2E_CHROMIUM_EXECUTABLE_PATH }
      : undefined,
  },
})
