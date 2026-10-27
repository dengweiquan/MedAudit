<template>
  <div class="card">
    <h2>管理说明</h2>
    <p class="todo">本页为工程师管理面：医院与对象的登记、参数修改、归类与删除。客户日常只需在类别页点「开始审计」与「导出报告」。删除只移除资产登记，历史事实包/问题/报告作为审计证据保留。工程师也可使用 ma 命令（如 ma assetadd、ma rules、ma baseexempt、ma srv）。</p>
    <div class="msg" v-if="msg">{{ msg }}</div>
    <div class="msg err" v-if="err">{{ err }}</div>
  </div>

  <div class="card" v-if="site?.hospital_id">
    <h2>本站信息</h2>
    <table>
      <tbody>
        <tr><td style="width:120px">医院 ID</td><td>{{ site.hospital_id }}</td></tr>
        <tr><td>医院名称</td><td>{{ site.name }}</td></tr>
      </tbody>
    </table>
    <div class="todo">本平台为单院部署：本站医院在系统初始化时给定，本页不提供多医院管理。登记的所有对象自动归属本站。如需变更本站信息，由工程师修改服务端初始化参数（MEDAUDIT_SITE_HOSPITAL_ID / NAME）后重启服务。当前查看医院已锁定为本站，工作台与各类别页只显示本站信息。</div>
  </div>

  <div class="card" v-else>
    <h2>医院登记</h2>
    <table v-if="hospitals.length">
      <thead><tr><th>ID</th><th>名称</th><th>登记时间</th></tr></thead>
      <tbody>
        <tr v-for="h in hospitals" :key="h.id"><td>{{ h.id }}</td><td>{{ h.name }}</td><td>{{ fmtLocal(h.created_at) }}</td></tr>
      </tbody>
    </table>
    <div class="inline-form" style="margin-top:8px">
      <input v-model="hForm.id" placeholder="医院 ID，如 hosp-001" />
      <input v-model="hForm.name" placeholder="医院名称" style="min-width:220px" />
      <button class="btn primary" @click="createHospital">新建医院</button>
    </div>
    <div class="todo">本站尚未初始化（当前为多院开发/测试模式）。客户部署在初始化时给定本站医院后，本节自动变为「本站信息」。名称为 auto-created:* 的是导入时自动生成的占位登记。</div>
  </div>

  <div class="card" v-if="!site?.hospital_id">
    <h2>当前查看医院</h2>
    <div class="inline-form">
      <select v-model="viewHospital" @change="onViewHospitalChange">
        <option value="">全部医院</option>
        <option v-for="h in hospitals" :key="h.id" :value="h.id">{{ h.id }}（{{ h.name }}）</option>
      </select>
      <span class="todo">选择后，工作台、数据库、操作系统、中间件、业务接口、审计记录、问题、报告、复检对比、关联分析只显示该医院的信息；刷新、换页后仍然有效。切回「全部医院」恢复全量。规则页不受影响（规则启停为本站级）。下方登记表单的医院缺省值跟随当前选择。</span>
    </div>
  </div>

  <div class="card" v-if="unclassified.length">
    <h2>待分类资产（{{ unclassified.length }}）</h2>
    <div class="todo" style="margin-bottom:8px">以下资产是早期导入自动生成的占位登记（类型 unknown），请选择正确类型保存，以便归入类别页管理。</div>
    <table>
      <thead><tr><th>ID</th><th>名称</th><th>医院</th><th>归类为</th><th></th></tr></thead>
      <tbody>
        <tr v-for="a in unclassified" :key="a.id">
          <td>{{ a.id }}</td><td>{{ a.name }}</td><td>{{ a.hospital_id }}</td>
          <td>
            <select v-model="fixKind[a.id]">
              <option value="db-oracle">数据库 · Oracle</option>
              <option value="db-sqlserver">数据库 · SQL Server</option>
              <option value="db-mysql">数据库 · MySQL</option>
              <option value="db-postgres">数据库 · PostgreSQL</option>
              <option value="host">操作系统 · 主机</option>
              <option value="api">业务接口</option>
              <option value="mw-other">中间件 · 其他</option>
            </select>
          </td>
          <td><button class="btn small primary" @click="fixAsset(a)">保存</button></td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>登记数据库</h2>
    <div class="form-grid">
      <label>数据库类型
        <select v-model="dbForm.kind" @change="onEngineChange">
          <option v-for="e in DB_ENGINES" :key="e.kind" :value="e.kind">{{ e.label }}</option>
        </select>
      </label>
      <label>资产 ID<input v-model="dbForm.id" placeholder="db-prod-01" /></label>
      <label v-if="site?.hospital_id">医院<input :value="site.name + '（' + site.hospital_id + '）'" disabled /></label>
      <label v-else>医院
        <select v-model="dbForm.hospital_id">
          <option v-for="h in hospitals" :key="h.id" :value="h.id">{{ h.id }}（{{ h.name }}）</option>
        </select>
      </label>
      <label>名称<input v-model="dbForm.name" placeholder="如：HIS 生产库" /></label>
      <label>主机<input v-model="dbForm.host" placeholder="10.0.0.12" /></label>
      <label>端口<input v-model.number="dbForm.port" type="number" /></label>
      <label>只读审计账号<input v-model="dbForm.user" placeholder="medaudit_reader" /></label>
      <label>{{ dbEngineLabel }}<input v-model="dbForm.dbname" :placeholder="dbForm.kind === 'db-oracle' ? '如 ORCLPDB1' : '如 hisdb'" /></label>
      <label v-if="dbForm.kind === 'db-postgres'">SSL 模式
        <select v-model="dbForm.sslmode">
          <option value="disable">disable</option>
          <option value="require">require</option>
          <option value="verify-ca">verify-ca</option>
          <option value="verify-full">verify-full</option>
        </select>
      </label>
    </div>
    <div class="inline-form">
      <button class="btn primary" @click="createDb">登记数据库</button>
    </div>
    <div class="todo">登记只保存连接参数（非机密信息）。<b>口令不保存</b>，在一键审计时输入、仅本次使用。请使用只读审计账号。</div>
  </div>

  <div class="card">
    <h2>登记主机</h2>
    <div class="form-grid">
      <label>资产 ID<input v-model="osForm.id" placeholder="host-his-01" /></label>
      <label v-if="site?.hospital_id">医院<input :value="site.name + '（' + site.hospital_id + '）'" disabled /></label>
      <label v-else>医院
        <select v-model="osForm.hospital_id">
          <option v-for="h in hospitals" :key="h.id" :value="h.id">{{ h.id }}（{{ h.name }}）</option>
        </select>
      </label>
      <label>名称<input v-model="osForm.name" placeholder="如：HIS 应用服务器（Linux）" /></label>
      <label>系统
        <select v-model="osForm.osKind">
          <option value="os-linux">Linux（SSH 推送）</option>
          <option value="os-windows">Windows（WinRM 推送）</option>
          <option value="os-hpux">HP-UX 11i v3（SSH 命令采集）</option>
          <option value="host">未定（仅登记）</option>
        </select>
      </label>
      <label>地址<input v-model="osForm.endpoint" placeholder="10.0.0.21（备注用）" /></label>
      <label>远程主机<input v-model="osForm.host" placeholder="远程审计用，如 10.0.0.21（可空）" /></label>
      <label>远程端口<input v-model="osForm.port" placeholder="SSH 22 / WinRM 5985（可空）" /></label>
      <label>登录账号<input v-model="osForm.user" placeholder="远程审计账号（可空）" /></label>
      <label v-if="osForm.osKind === 'os-windows'">服务回连地址<input v-model="osForm.server_url" placeholder="目标机可达的本服务地址（Windows 必填）" /></label>
      <label v-if="osForm.osKind === 'os-linux' || osForm.osKind === 'os-hpux'">SSH 主机密钥指纹<input v-model="osForm.host_key" placeholder="SHA256:...（可空，空=首次接受并回显）" /></label>
      <label v-if="osForm.osKind === 'os-linux'">服务白名单<input v-model="osForm.services" placeholder="逗号分隔，如 ssh.service,docker.service（可空，空=自动枚举运行中服务）" /></label>
    </div>
    <div class="inline-form">
      <button class="btn primary" @click="createOs">登记主机</button>
    </div>
    <div class="todo">登记了远程参数（主机+账号）的主机可由服务端推送采集器远程审计：口令在审计时输入、仅本次使用不保存。</div>
  </div>

  <div class="card">
    <h2>登记中间件</h2>
    <div class="form-grid">
      <label>产品
        <select v-model="mwForm.kind">
          <option v-for="p in MW_PRODUCTS" :key="p.kind" :value="p.kind">{{ p.label }}{{ p.supported ? '（已支持采集）' : '（仅登记）' }}</option>
        </select>
      </label>
      <label>资产 ID<input v-model="mwForm.id" placeholder="mw-his-01" /></label>
      <label v-if="site?.hospital_id">医院<input :value="site.name + '（' + site.hospital_id + '）'" disabled /></label>
      <label v-else>医院
        <select v-model="mwForm.hospital_id">
          <option v-for="h in hospitals" :key="h.id" :value="h.id">{{ h.id }}（{{ h.name }}）</option>
        </select>
      </label>
      <label>名称<input v-model="mwForm.name" placeholder="如：HIS 中间件（Tomcat）" /></label>
      <label>安装目录 / 端点<input v-model="mwForm.endpoint" placeholder="如 /opt/tomcat9 或 10.0.0.21:8080" /></label>
      <label>版本<input v-model="mwForm.version" placeholder="如 9.0.85（可选）" /></label>
      <label>远程主机<input v-model="mwForm.host" placeholder="远程审计用（可空）" /></label>
      <label>远程端口<input v-model="mwForm.port" placeholder="SSH 22 / WinRM 5985（可空）" /></label>
      <label>登录账号<input v-model="mwForm.user" placeholder="远程审计账号（可空）" /></label>
      <label>采集目录<input v-model="mwForm.mw_home" placeholder="目标机上的安装/配置目录（远程审计用）" /></label>
      <label v-if="mwForm.kind === 'mw-iis'">服务回连地址<input v-model="mwForm.server_url" placeholder="目标机可达的本服务地址（IIS 必填）" /></label>
    </div>
    <div class="inline-form">
      <button class="btn primary" @click="createMw">登记中间件</button>
    </div>
  </div>

  <div class="card">
    <h2>资产总表（{{ assets.length }}）</h2>
    <div class="todo" v-if="viewHospital">当前只显示 {{ viewHospital }} 的资产；切回「全部医院」可见全部。</div>
    <div class="inline-form" v-if="delSelected.size" style="margin-bottom:8px">
      <span>已选 {{ delSelected.size }} 条</span>
      <button class="btn small" @click="batchDelete">批量删除</button>
      <button class="btn small" @click="delSelected.clear()">清空选择</button>
    </div>
    <div v-if="error" class="error">{{ error }}</div>
    <table v-else>
      <thead><tr><th></th><th>ID</th><th>名称</th><th>医院</th><th>类型</th><th>端点</th><th>参数</th><th>事实包</th><th></th></tr></thead>
      <tbody>
        <template v-for="a in assets" :key="a.id">
          <tr>
            <td><input type="checkbox" :checked="delSelected.has(a.id)" @change="toggleDel(a.id)" /></td>
            <td>{{ a.id }}</td><td>{{ a.name }}</td><td>{{ a.hospital_id }}</td><td>{{ a.kind }}</td>
            <td>{{ a.endpoint ?? '—' }}</td>
            <td><span v-if="a.labels" class="concl c-PASS">已登记</span><span v-else class="concl c-UNKNOWN">无</span></td>
            <td>{{ bundleCountOf(a.id) }}</td>
            <td>
              <div class="row-actions">
                <button class="btn small" @click="startEdit(a)">编辑</button>
                <button class="btn small" @click="doDelete(a)">删除</button>
              </div>
            </td>
          </tr>
          <tr v-if="editId === a.id">
            <td colspan="9">
              <div class="form-grid">
                <label>名称<input v-model="editForm.name" /></label>
                <label>类型<input v-model="editForm.kind" /></label>
                <label>端点<input v-model="editForm.endpoint" /></label>
              </div>
              <label style="display:block;margin:6px 0">labels（JSON：数据库为 ConnConfig，远程资产为 RemoteConfig）
                <textarea v-model="editForm.labels" rows="4" style="width:100%"></textarea>
              </label>
              <div class="inline-form">
                <button class="btn primary" @click="saveEdit(a)">保存</button>
                <button class="btn" @click="editId = ''">取消</button>
                <span class="msg err" v-if="editErr">{{ editErr }}</span>
              </div>
              <div class="todo">数据库资产的连接参数请优先用类别对应的结构化方式维护（ConnConfig: engine/host/port/user/dbname|service/sslmode）；此处为通用编辑，保存前请确认 JSON 合法。</div>
            </td>
          </tr>
        </template>
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>用户管理（{{ users.length }}）</h2>
    <table v-if="users.length">
      <thead><tr><th>用户名</th><th>状态</th><th>强制改密</th><th>创建时间</th><th></th></tr></thead>
      <tbody>
        <tr v-for="u in users" :key="u.username">
          <td>{{ u.username }}</td>
          <td><span class="concl" :class="u.disabled ? 'c-FAIL' : 'c-PASS'">{{ u.disabled ? '已禁用' : '正常' }}</span></td>
          <td>{{ u.must_change_pwd ? '是' : '否' }}</td>
          <td>{{ fmtLocal(u.created_at) }}</td>
          <td>
            <div class="row-actions">
              <button class="btn small" @click="resetTarget = resetTarget === u.username ? '' : u.username; resetPw = ''">重置口令</button>
              <button class="btn small" @click="toggleUserDisabled(u)">{{ u.disabled ? '启用' : '禁用' }}</button>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
    <div class="inline-form" v-if="resetTarget" style="margin-top:8px">
      <span>重置 {{ resetTarget }} 的口令：</span>
      <input v-model="resetPw" type="password" placeholder="新口令（至少 8 位）" autocomplete="new-password" />
      <button class="btn primary small" @click="doResetPw">确认重置</button>
      <button class="btn small" @click="resetTarget = ''">取消</button>
    </div>
    <div class="form-grid" style="margin-top:10px">
      <label>新用户名<input v-model="nuForm.username" placeholder="如 engineer1（字母/数字/_/-/.）" /></label>
      <label>初始口令<input v-model="nuForm.password" type="password" placeholder="至少 8 位；新用户首登强制改密" autocomplete="new-password" /></label>
    </div>
    <div class="inline-form">
      <button class="btn primary" @click="doCreateUser">新建用户</button>
      <span class="msg" v-if="userMsg">{{ userMsg }}</span>
      <span class="msg err" v-if="userErr">{{ userErr }}</span>
    </div>
    <div class="todo">禁用或重置口令会立即吊销该用户的全部会话；不能禁用自己与最后一个可用账号（服务端校验）。所有账号当前同权（无角色分级）。</div>
  </div>

  <ScheduleCard />

  <OpLogCard />
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { api, type Asset, type BundleSummary, type ConnConfig, type Hospital, type SiteInfo, type UserRow } from '../api'
import { DB_ENGINES, engineOfKind, kindCategory } from '../categories'
import { loadSite, fmtLocal} from '../util'
import { selectedHospital, setHospital, filterByHospital } from '../store'
import OpLogCard from '../components/OpLogCard.vue'
import ScheduleCard from '../components/ScheduleCard.vue'

// 当前查看医院（管理页的选择器即全局筛选的唯一入口）。
const viewHospital = ref('')
async function onViewHospitalChange() {
  setHospital(viewHospital.value)
  await load()
}

const site = ref<SiteInfo | null>(null)

const MW_PRODUCTS = [
  { kind: 'mw-tomcat', label: 'Tomcat', supported: true },
  { kind: 'mw-nginx', label: 'Nginx', supported: true },
  { kind: 'mw-weblogic', label: 'WebLogic', supported: true },
  { kind: 'mw-iis', label: 'IIS', supported: true },
  { kind: 'mw-other', label: '其他中间件', supported: false },
]

const hospitals = ref<Hospital[]>([])
const assets = ref<Asset[]>([])
const bundles = ref<BundleSummary[]>([])
const delSelected = reactive(new Set<string>())
function bundleCountOf(id: string): number { return bundles.value.filter(b => b.asset_id === id).length }
function toggleDel(id: string) { delSelected.has(id) ? delSelected.delete(id) : delSelected.add(id) }

async function doDelete(a: Asset) {
  const n = bundleCountOf(a.id)
  const warn = n ? `该对象已有 ${n} 个事实包：删除只移除登记，历史事实包/问题/报告作为审计证据保留。` : '该对象尚无事实包。'
  if (!window.confirm(`确认删除资产 ${a.id}（${a.name}）？\n${warn}`)) return
  try {
    await api.deleteAsset(a.id)
    note(`资产 ${a.id} 已删除（历史事实包保留）`)
    delSelected.delete(a.id)
    await load()
  } catch (e) { fail(e, '删除失败') }
}

async function batchDelete() {
  const ids = [...delSelected]
  if (!window.confirm(`确认批量删除 ${ids.length} 个资产？\n删除只移除登记，历史事实包/问题/报告保留。`)) return
  let ok = 0
  for (const id of ids) {
    try { await api.deleteAsset(id); ok++ } catch (e) { fail(e, '删除失败') }
  }
  note(`批量删除完成：${ok}/${ids.length}`)
  delSelected.clear()
  await load()
}
const error = ref('')
const msg = ref('')
const err = ref('')
const hForm = ref({ id: '', name: '' })
const fixKind = reactive<Record<string, string>>({})

const unclassified = computed(() => assets.value.filter(a => kindCategory(a.kind) === 'unknown'))

async function load() {
  try {
    site.value = await loadSite()
    hospitals.value = await api.hospitals()
    // 单院锁定本站；多院模式下已删医院的残留选择清回全部。
    if (site.value?.hospital_id) setHospital(site.value.hospital_id)
    else if (selectedHospital.id && !hospitals.value.some(h => h.id === selectedHospital.id)) setHospital('')
    viewHospital.value = selectedHospital.id
    const allAssets = await api.assets()
    assets.value = filterByHospital(allAssets)
    try { bundles.value = filterByHospital(await api.bundles()) } catch { bundles.value = [] }
    try { users.value = await api.users() } catch { users.value = [] }
    if (site.value?.hospital_id) {
      // 单院部署：登记自动归属本站
      dbForm.value.hospital_id = site.value.hospital_id
      osForm.value.hospital_id = site.value.hospital_id
      mwForm.value.hospital_id = site.value.hospital_id
    } else if (viewHospital.value) {
      // 多院模式：登记表单缺省跟随当前查看医院
      dbForm.value.hospital_id = viewHospital.value
      osForm.value.hospital_id = viewHospital.value
      mwForm.value.hospital_id = viewHospital.value
    }
    for (const a of assets.value) if (kindCategory(a.kind) === 'unknown') fixKind[a.id] = 'host'
    if (!dbForm.value.hospital_id && hospitals.value.length) dbForm.value.hospital_id = hospitals.value[0].id
    if (!osForm.value.hospital_id && hospitals.value.length) osForm.value.hospital_id = hospitals.value[0].id
    if (!mwForm.value.hospital_id && hospitals.value.length) mwForm.value.hospital_id = hospitals.value[0].id
  } catch (e) { error.value = e instanceof Error ? e.message : '加载失败' }
}

// ---- M20 用户管理 ----
const users = ref<UserRow[]>([])
const nuForm = ref({ username: '', password: '' })
const resetTarget = ref('')
const resetPw = ref('')
const userMsg = ref('')
const userErr = ref('')
function userNote(ok: string) { userMsg.value = ok; userErr.value = '' }
function userFail(e: unknown) { userErr.value = e instanceof Error ? e.message : '操作失败'; userMsg.value = '' }
async function doCreateUser() {
  try {
    await api.createUser(nuForm.value.username.trim(), nuForm.value.password)
    userNote(`用户 ${nuForm.value.username} 已创建（首登强制改密）`)
    nuForm.value = { username: '', password: '' }
    users.value = await api.users()
  } catch (e) { userFail(e) }
}
async function doResetPw() {
  try {
    await api.resetUserPassword(resetTarget.value, resetPw.value)
    userNote(`已重置 ${resetTarget.value} 的口令（其会话已吊销）`)
    resetTarget.value = ''; resetPw.value = ''
    users.value = await api.users()
  } catch (e) { userFail(e) }
}
async function toggleUserDisabled(u: UserRow) {
  try {
    await api.setUserDisabled(u.username, !u.disabled)
    userNote(`用户 ${u.username} 已${u.disabled ? '启用' : '禁用'}`)
    users.value = await api.users()
  } catch (e) { userFail(e) }
}

function note(ok: string) { msg.value = ok; err.value = '' }
function fail(e: unknown, dft: string) { err.value = e instanceof Error ? e.message : dft; msg.value = '' }

async function createHospital() {
  try {
    await api.createHospital(hForm.value.id, hForm.value.name)
    note(`医院 ${hForm.value.id} 已登记`)
    hForm.value = { id: '', name: '' }
    await load()
  } catch (e) { fail(e, '登记失败') }
}

async function fixAsset(a: Asset) {
  try {
    await api.updateAsset(a.id, { kind: fixKind[a.id], name: a.name, endpoint: a.endpoint, labels: a.labels ?? null })
    note(`${a.id} 已归类为 ${fixKind[a.id]}`)
    await load()
  } catch (e) { fail(e, '保存失败') }
}

// ---- 数据库登记 ----
const dbForm = ref({ kind: 'db-mysql', id: '', hospital_id: '', name: '', host: '', port: 3306, user: '', dbname: '', sslmode: 'disable' })
const dbEngineLabel = computed(() => engineOfKind(dbForm.value.kind)?.dbLabel ?? '数据库名')
function onEngineChange() {
  const e = engineOfKind(dbForm.value.kind)
  if (e) dbForm.value.port = e.defaultPort
}
function buildLabels(kind: string, f: { host: string; port: number; user: string; dbname: string; sslmode: string }): string {
  const e = engineOfKind(kind)
  const conn: ConnConfig = { engine: e?.engine ?? '', host: f.host, port: f.port, user: f.user }
  if (e?.dbField === 'service') conn.service = f.dbname
  else if (f.dbname) conn.dbname = f.dbname
  if (kind === 'db-postgres' && f.sslmode) conn.sslmode = f.sslmode
  return JSON.stringify(conn)
}
async function createDb() {
  try {
    const f = dbForm.value
    await api.createAsset({
      id: f.id, hospital_id: f.hospital_id, kind: f.kind, name: f.name,
      endpoint: `${f.host}:${f.port}`, labels: buildLabels(f.kind, f),
    })
    note(`数据库 ${f.id} 已登记，可在类别页一键审计`)
    dbForm.value.id = ''; dbForm.value.name = ''
    await load()
  } catch (e) { fail(e, '登记失败') }
}

// ---- 主机登记 ----
const osForm = ref({ id: '', hospital_id: '', name: '', endpoint: '', osKind: 'os-linux', host: '', port: '', user: '', server_url: '', host_key: '', services: '' })
async function createOs() {
  try {
    const f = osForm.value
    const labels = f.host && f.user ? JSON.stringify({
      transport: f.osKind === 'os-windows' ? 'winrm' : 'ssh',
      host: f.host, port: f.port ? Number(f.port) : undefined, user: f.user,
      server_url: f.server_url || undefined, host_key: f.host_key || undefined,
      services: f.services || undefined,
    }) : undefined
    await api.createAsset({
      id: f.id, hospital_id: f.hospital_id, kind: f.osKind,
      name: f.name, endpoint: f.endpoint || f.host || null, labels,
    })
    note(`主机 ${f.id} 已登记` + (labels ? '，可远程审计' : ''))
    osForm.value.id = ''; osForm.value.name = ''
    await load()
  } catch (e) { fail(e, '登记失败') }
}

// ---- 中间件登记 ----
const mwForm = ref({ kind: 'mw-tomcat', id: '', hospital_id: '', name: '', endpoint: '', version: '', host: '', port: '', user: '', mw_home: '', server_url: '' })
async function createMw() {
  try {
    const f = mwForm.value
    const mwHome = f.mw_home || (f.endpoint && (f.endpoint.startsWith('/') || /^[A-Za-z]:\\/.test(f.endpoint)) ? f.endpoint : '')
    const labels: Record<string, unknown> = { product: MW_PRODUCTS.find(p => p.kind === f.kind)?.label ?? f.kind, version: f.version }
    if (f.host && f.user) {
      labels.transport = f.kind === 'mw-iis' ? 'winrm' : 'ssh'
      labels.host = f.host
      if (f.port) labels.port = Number(f.port)
      labels.user = f.user
      if (mwHome) labels.mw_home = mwHome
      if (f.server_url) labels.server_url = f.server_url
    }
    await api.createAsset({
      id: f.id, hospital_id: f.hospital_id, kind: f.kind, name: f.name,
      endpoint: f.endpoint || null, labels: JSON.stringify(labels),
    })
    note(`中间件 ${f.id} 已登记`)
    mwForm.value.id = ''; mwForm.value.name = ''
    await load()
  } catch (e) { fail(e, '登记失败') }
}

// ---- 通用编辑 ----
const editId = ref('')
const editErr = ref('')
const editForm = ref({ name: '', kind: '', endpoint: '', labels: '' })
function startEdit(a: Asset) {
  editId.value = a.id
  editErr.value = ''
  editForm.value = { name: a.name, kind: a.kind, endpoint: a.endpoint ?? '', labels: a.labels ?? '' }
}
async function saveEdit(a: Asset) {
  editErr.value = ''
  const labels = editForm.value.labels.trim()
  if (labels) {
    try { JSON.parse(labels) } catch { editErr.value = 'labels 不是合法 JSON'; return }
  }
  try {
    await api.updateAsset(a.id, {
      kind: editForm.value.kind, name: editForm.value.name,
      endpoint: editForm.value.endpoint || null,
      labels: labels || null,
    })
    editId.value = ''
    note(`资产 ${a.id} 已更新`)
    await load()
  } catch (e) { editErr.value = e instanceof Error ? e.message : '保存失败' }
}

onMounted(load)
</script>
