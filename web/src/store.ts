import { reactive } from 'vue'

// 跨视图导航的最小共享状态：当前视图 + 聚焦的事实包。
export const nav = reactive({
  view: 'dashboard' as string,
  bundleId: '' as string,
  assetId: '' as string,
})

export function goto(view: string, bundleId?: string) {
  nav.view = view
  if (bundleId !== undefined) nav.bundleId = bundleId
}

export function gotoAsset(view: string, assetId: string) {
  nav.view = view
  nav.assetId = assetId
}

export function reviewerName(): string {
  return localStorage.getItem('medaudit-reviewer') || ''
}

export function saveReviewerName(name: string) {
  localStorage.setItem('medaudit-reviewer', name)
}
