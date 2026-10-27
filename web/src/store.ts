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

// 全局当前医院筛选：在「管理」页选择，其他页跟随；空串 = 全部医院。
// 刷新、换页后仍有效（localStorage）；单院部署时管理页会把它锁定为本站。
const HOSPITAL_KEY = 'medaudit-hospital'
function loadHospital(): string {
  try { return localStorage.getItem(HOSPITAL_KEY) || '' } catch { return '' }
}
export const selectedHospital = reactive({ id: loadHospital() })

export function setHospital(id: string) {
  selectedHospital.id = id
  try {
    if (id) localStorage.setItem(HOSPITAL_KEY, id)
    else localStorage.removeItem(HOSPITAL_KEY)
  } catch { /* 隐私模式等写失败时仅本次会话有效 */ }
}

// 工程师模式：只切换界面显示（菜单与详情层级），不是权限控制——
// 现在所有账号同权，开关旁悬停提示写明。状态存 localStorage，读写包 try/catch。
const ENGINEER_KEY = 'medaudit-engineer-mode'
function loadEngineer(): boolean {
  try { return localStorage.getItem(ENGINEER_KEY) === '1' } catch { return false }
}
export const engineerMode = reactive({ on: loadEngineer() })

export function setEngineerMode(on: boolean) {
  engineerMode.on = on
  try {
    if (on) localStorage.setItem(ENGINEER_KEY, '1')
    else localStorage.removeItem(ENGINEER_KEY)
  } catch { /* 隐私模式等写失败时仅本次会话有效 */ }
}

// 带 hospital_id 的行是否属于当前所选医院（空选 = 全部）。
export function inSelectedHospital(hospitalId: string): boolean {
  return !selectedHospital.id || selectedHospital.id === hospitalId
}
export function filterByHospital<T extends { hospital_id: string }>(rows: T[]): T[] {
  return selectedHospital.id ? rows.filter(r => r.hospital_id === selectedHospital.id) : rows
}

export function reviewerName(): string {
  return localStorage.getItem('medaudit-reviewer') || ''
}

export function saveReviewerName(name: string) {
  localStorage.setItem('medaudit-reviewer', name)
}
