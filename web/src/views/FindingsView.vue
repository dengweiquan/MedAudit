<template>
  <div class="card">
    <h2>问题列表</h2>
    <div class="inline-form">
      <label>对象
        <select v-model="assetId" @change="onAssetChange">
          <option v-for="a in assetOptions" :key="a.id" :value="a.id">{{ a.name }}</option>
        </select>
      </label>
      <label v-if="engineerMode.on">审计记录
        <select v-model="bundleId" @change="load">
          <option v-for="b in bundlesOfAsset" :key="b.id" :value="b.id">{{ bundleLabel(b) }}</option>
        </select>
      </label>
      <span class="todo" v-if="current">最近审计 {{ fmtLocal(current.imported_at) }}</span>
      <label class="todo"><input type="checkbox" v-model="latestOnly" /> 只看最新一轮评估</label>
    </div>
    <div class="chips">
      <button class="chip" :class="{ active: filter === '' }" @click="filter = ''">全部 {{ runRows.length }}</button>
      <button v-for="c in conclusions" :key="c" class="chip" :class="{ active: filter === c }" @click="filter = c">
        {{ conclLabel(c) }} {{ runRows.filter(f => f.conclusion === c).length }}
      </button>
    </div>
    <p class="todo" v-if="runRows.length">
      当前口径共 <b>{{ groups.length }} 类问题</b>、{{ filtered.length }} 条（按风险分组，展开看账号与明细）。
      <span v-if="!latestOnly">含全部历史轮次，同一问题会重复出现。</span>
    </p>
    <div v-if="error" class="error">{{ error }}</div>
    <table v-else-if="rulesReady && groups.length">
      <thead><tr><th>问题名称</th><th>风险</th><th>涉及账号</th><th></th><th></th></tr></thead>
      <tbody>
        <template v-for="g in groups" :key="g.ruleId">
          <tr class="clickable" :class="{ selected: openRule === g.ruleId }" @click="openRule = openRule === g.ruleId ? '' : g.ruleId">
            <td><b :title="engineerMode.on ? g.ruleId : undefined">{{ ruleName(g.ruleId) }}</b><div class="todo" v-if="engineerMode.on">{{ g.ruleId }}</div></td>
            <td><span class="concl" :class="'risk-' + (ruleOf(g.ruleId)?.Risk ?? '')">{{ riskLabel(ruleOf(g.ruleId)?.Risk) }}</span></td>
            <td>{{ g.subjects.length }}</td>
            <td><button class="btn small primary" @click.stop="openHowTo(g)">怎么改</button></td>
            <td>{{ openRule === g.ruleId ? '收起' : '展开' }}</td>
          </tr>
          <tr v-if="openRule === g.ruleId">
            <td colspan="5">
              <p v-if="ruleOf(g.ruleId)" style="margin:4px 0">{{ ruleOf(g.ruleId)?.Description }}<br /><b>如何解决：</b>{{ ruleOf(g.ruleId)?.Remediation }}</p>
              <table>
                <thead><tr><th>账号</th><th>条数</th><th>结论</th><th></th></tr></thead>
                <tbody>
                  <template v-for="s in visibleSubjects(g)" :key="g.ruleId + '|' + s.subject">
                    <tr class="clickable" @click="toggleSubject(g.ruleId, s.subject)">
                      <td>{{ subjectLabel(s.subject) }}<div class="todo" v-if="engineerMode.on && subjectLabel(s.subject) !== s.subject">{{ s.subject }}</div></td>
                      <td>{{ s.rows.length }}</td>
                      <td><span v-for="c in subjectConclusions(s.rows)" :key="c" class="concl" :class="'c-' + c" style="margin-right:4px">{{ conclLabel(c) }}</span></td>
                      <td>{{ openSubject === g.ruleId + '|' + s.subject ? '收起' : '明细' }}</td>
                    </tr>
                    <tr v-if="openSubject === g.ruleId + '|' + s.subject">
                      <td colspan="4">
                        <table>
                          <tbody>
                            <template v-for="f in s.rows.slice(0, 30)" :key="f.id">
                              <tr class="clickable" :class="{ selected: openId === f.id }" @click="toggle(f)">
                                <td v-if="engineerMode.on" style="width:60px">{{ f.id }}</td>
                                <td>{{ detailText(f) || f.subject }}</td>
                                <td><span class="concl" :class="'c-' + f.conclusion">{{ conclLabel(f.conclusion) }}</span></td>
                                <td><span class="concl" :class="'rev-' + f.review_status">{{ reviewLabel(f.review_status) }}</span></td>
                                <td>{{ fmtLocal(f.created_at) }}</td>
                                <td>{{ openId === f.id ? '收起' : '详情' }}</td>
                              </tr>
                              <tr v-if="openId === f.id">
                                <td :colspan="engineerMode.on ? 6 : 5">
                                  <h3>结论：{{ f.conclusion === 'FAIL' ? '有问题，需处理' : f.conclusion === 'UNKNOWN' ? '证据不足，需人工确认' : conclLabel(f.conclusion) }}</h3>
                                  <p v-if="ruleOf(f)"><b>{{ ruleOf(f)?.Name }}</b> · 风险等级 {{ riskLabel(ruleOf(f)?.Risk) }}</p>
                                  <p><b>问题原因：</b>{{ f.subject }}：{{ detailText(f) || f.subject }}<span v-if="ruleOf(f)">。{{ ruleOf(f)?.Description }}</span></p>
                                  <div>
                                    <p><b>如何解决：</b></p>
                                    <p v-if="fixMap.get(f.id) === undefined" class="todo">正在取修复命令…</p>
                                    <template v-else-if="fixMap.get(f.id)?.supported && fixMap.get(f.id)?.script">
                                      <p class="todo">以下命令由平台按本问题证据生成，仅供人工评审后执行；平台不自动修改目标权限。</p>
                                      <pre>{{ fixMap.get(f.id)?.script?.fix }}</pre>
                                      <button class="btn small" @click="copyFix(fixMap.get(f.id)?.script?.fix || '')">{{ copiedFix ? '已复制' : '复制修复命令' }}</button>
                                      <p style="margin-top:8px"><b>执行前检查：</b></p>
                                      <pre>{{ fixMap.get(f.id)?.script?.precheck }}</pre>
                                      <p><b>验证：</b></p>
                                      <pre>{{ fixMap.get(f.id)?.script?.verify }}</pre>
                                      <p><b>回滚：</b></p>
                                      <pre>{{ fixMap.get(f.id)?.script?.rollback }}</pre>
                                      <p v-if="fixMap.get(f.id)?.script?.note"><b>注意：</b>{{ fixMap.get(f.id)?.script?.note }}</p>
                                    </template>
                                    <template v-else>
                                      <p>{{ ruleOf(f)?.Remediation }}</p>
                                      <p class="todo">该检查项暂无逐条修复命令；需要完整脚本清单请生成报告后在报告详情中查看，或由工程师用 ma reportfix 导出。</p>
                                    </template>
                                  </div>
                                  <p v-if="f.conclusion === 'FAIL'"><b>不解决怎么办：</b>确认为业务必需的例外时，点「加基线屏蔽」，之后评估默认自动套用本院基线，该条不再报警。<button class="btn" @click="openExempt(f)">加基线屏蔽</button></p>

                                  <template v-if="f.conclusion === 'FAIL'">
                                    <h3>加入基线（确认是例外时）</h3>
                                    <p class="todo">确认为业务必需的例外时，可把这一条加入基线。<span title="如厂商账号固有权限；加入后，之后评估默认自动套用本院基线，这一条不再计为问题；加入基线只影响平台结论，不修改目标系统。">?</span></p>
                                    <div class="inline-form">
                                      <button class="btn" @click="openExempt(f)">加入基线…</button>
                                    </div>
                                    <div v-if="exempt && exempt.forId === f.id" style="margin-top:8px">
                                      <p v-if="exempt.loading" class="todo">正在推导放行项…</p>
                                      <template v-else-if="exempt.preview && !exempt.preview.supported">
                                        <p class="todo">该检查项不支持基线豁免。如需整类停用，请到「规则」页关闭该检查项（须填写原因）。</p>
                                      </template>
                                      <template v-else-if="exempt.preview">
                                        <p style="margin:4px 0">将加入的放行项（由该问题的证据自动推导，无需手填）：</p>
                                        <div v-for="(a, i) in exempt.preview.allows ?? []" :key="i" style="font-size:13px">
                                          {{ a.Subject }} · {{ baselineKindLabel(a.Kind) }} = {{ a.Value }}<span class="todo" v-if="a.Scope"> · 范围 {{ a.Scope }}</span>
                                        </div>
                                        <div class="inline-form" style="margin-top:6px">
                                          <label>基线
                                            <select v-model="exempt.choice">
                                              <option v-for="b in exempt.baselines" :key="b.id" :value="b.id">{{ b.id }}（已有基线）</option>
                                              <option value="new">＋ 新建基线</option>
                                            </select>
                                          </label>
                                          <input v-if="exempt.choice === 'new'" v-model="exempt.newId" placeholder="新基线 ID" style="min-width:200px" />
                                          <input v-model="exempt.reason" placeholder="原因（如：厂商维护账号，业务必需）" style="min-width:260px" />
                                          <button class="btn primary" :disabled="exempt.busy" @click="doExempt(f)">确认加入</button>
                                        </div>
                                        <p class="todo">加入后默认随下一次评估自动生效；也可点下方按钮立即用该基线重新评估。</p>
                                      </template>
                                      <span class="msg" v-if="exempt.msg">{{ exempt.msg }}</span>
                                      <div v-if="exempt.msg && exempt.doneBaseline" style="margin-top:6px">
                                        <button class="btn small" :disabled="exempt.busy" @click="reevalWithBaseline(f)">用该基线重新评估本包</button>
                                        <span class="msg" v-if="exempt.reevalMsg">{{ exempt.reevalMsg }}</span>
                                      </div>
                                      <span class="msg err" v-if="exempt.err">{{ exempt.err }}</span>
                                    </div>
                                  </template>

                                  <h3>判定详情</h3>
                                  <div v-if="detailInfo(f)">
                                    <p><b>问题：</b>{{ detailInfo(f)?.detail }}</p>
                                    <p v-if="detailInfo(f)?.evidence?.length"><b>证据：</b>{{ detailInfo(f)?.evidence?.join('、') }}</p>
                                    <p v-if="detailInfo(f)?.missing"><b>缺失：</b>{{ detailInfo(f)?.missing }}</p>
                                    <p v-if="detailInfo(f)?.risk"><b>风险：</b>{{ detailInfo(f)?.risk }}</p>
                                  </div>
                                  <pre v-else>{{ pretty(f.detail) }}</pre>

                                  <h3>人工复核</h3>
                                  <div class="inline-form">
                                    <select v-model="reviewForm.decision">
                                      <option value="confirmed">确认问题（confirmed）</option>
                                      <option value="false_positive">误报（false_positive）</option>
                                      <option value="exception">例外（exception）</option>
                                    </select>
                                    <input v-model="reviewForm.comment" placeholder="复核备注" style="min-width:220px" />
                                    <input v-model="reviewForm.reviewer" placeholder="复核人" @change="saveReviewerName(reviewForm.reviewer)" />
                                    <button class="btn primary" @click="doReview(f)">提交复核</button>
                                    <span class="msg" v-if="opMsg">{{ opMsg }}</span>
                                    <span class="msg err" v-if="opErr">{{ opErr }}</span>
                                  </div>

                                  <h3>整改记录</h3>
                                  <table v-if="remediations.length">
                                    <thead><tr><th>措施</th><th>状态</th><th>执行人</th><th>完成时间</th><th>登记时间</th></tr></thead>
                                    <tbody>
                                      <tr v-for="r in remediations" :key="r.id">
                                        <td>{{ r.action }}</td><td>{{ r.status }}</td><td>{{ r.acted_by }}</td>
                                        <td>{{ r.acted_at ? fmtLocal(r.acted_at) : '—' }}</td><td>{{ fmtLocal(r.created_at) }}</td>
                                      </tr>
                                    </tbody>
                                  </table>
                                  <div v-else class="empty">暂无整改记录。</div>
                                  <div class="inline-form">
                                    <input v-model="remForm.action" placeholder="整改措施（经现有变更流程执行）" style="min-width:280px" />
                                    <select v-model="remForm.status">
                                      <option value="pending">进行中（pending）</option>
                                      <option value="done">已完成（done）</option>
                                    </select>
                                    <input v-model="remForm.acted_by" placeholder="执行人" />
                                    <button class="btn" @click="doRemediation(f)">登记整改</button>
                                  </div>

                                  <h3>复测</h3>
                                  <div class="inline-form">
                                    <select v-model="retestBundle">
                                      <option value="">选择同资产的复测事实包…</option>
                                      <option v-for="b in sameAssetBundles(f)" :key="b.id" :value="b.id">{{ engineerMode.on ? b.id + '（' + fmtLocal(b.imported_at) + '）' : fmtLocal(b.imported_at) }}</option>
                                    </select>
                                    <button class="btn primary" :disabled="!retestBundle" @click="doRetest(f)">执行复测</button>
                                    <span class="todo">复测以新包做技术口径（无基线）重评估，比对同规则同账号。</span>
                                  </div>
                                  <table v-if="retests.length">
                                    <thead><tr><th>复测包</th><th>结论</th><th>时间</th></tr></thead>
                                    <tbody>
                                      <tr v-for="r in retests" :key="r.id">
                                        <td>{{ r.bundle_id }}</td>
                                        <td><span class="concl" :class="'c-' + r.conclusion">{{ conclLabel(r.conclusion) }}</span></td>
                                        <td>{{ fmtLocal(r.created_at) }}</td>
                                      </tr>
                                    </tbody>
                                  </table>
                                  <div v-else class="empty">暂无复测记录。</div>
                                </td>
                              </tr>
                            </template>
                          </tbody>
                        </table>
                        <p class="todo" v-if="s.rows.length > 30">该账号共 {{ s.rows.length }} 条，此处仅列前 30 条；完整清单见报告导出。</p>
                      </td>
                    </tr>
                  </template>
                </tbody>
              </table>
              <button v-if="g.subjects.length > subjectCap" class="btn small" @click="subjectCap += 100">显示更多账号（剩余 {{ g.subjects.length - subjectCap }}）</button>
            </td>
          </tr>
        </template>
      </tbody>
    </table>
    <div v-else-if="rulesReady" class="empty">该审计记录暂无问题（或尚未评估，去「审计记录」页的工程师详情里点评估）。</div>
    <div v-else class="empty">加载中…</div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, type Asset, type BaselineRow, type BundleSummary, type ExemptionPreview, type Finding, type FixScriptResp, type RemediationRow, type RetestRow, type Rule } from '../api'
import { nav, reviewerName, saveReviewerName, filterByHospital, engineerMode } from '../store'
import { latestRunFindings, loadFindingsWithRun, latestBundleOf, fmtLocal, baselineKindLabel } from '../util'
import { conclLabel, riskLabel, reviewLabel } from '../labels'

const bundles = ref<BundleSummary[]>([])
const assets = ref<Asset[]>([])
const latestByAsset = ref(new Map<string, BundleSummary>())
const assetId = ref('')
const bundleId = ref('')
const findings = ref<Finding[]>([])
const filter = ref('')
const latestOnly = ref(true)
const latestRunId = ref<number | undefined>(undefined)
const error = ref('')
const openRule = ref('')
const openSubject = ref('')
const subjectCap = ref(50)
const openId = ref(0)
const retests = ref<RetestRow[]>([])
const remediations = ref<RemediationRow[]>([])
const fixMap = ref<Map<number, FixScriptResp | null>>(new Map())
const copiedFix = ref(false)
const retestBundle = ref('')
const opMsg = ref('')
const opErr = ref('')
const reviewForm = ref({ decision: 'confirmed', comment: '', reviewer: reviewerName() })
const remForm = ref({ action: '', status: 'pending', acted_by: reviewerName() })
const rulesMap = ref<Map<string, Rule>>(new Map())
const rulesReady = ref(false)
let loadSeq = 0

function ruleOf(f: Finding | string): Rule | undefined {
  return rulesMap.value.get(typeof f === 'string' ? f : f.rule_id)
}
function ruleName(id: string): string { return rulesMap.value.get(id)?.Name ?? id }
function detailText(f: Finding): string {
  try {
    const d = JSON.parse(f.detail) as { detail?: string }
    return d.detail ?? ''
  } catch { return '' }
}
// M33：proc_key 形主体（主机/启动 ID/PID/启动时间）只显示进程 PID，完整键仍在下方小字保留。
function subjectLabel(subject: string): string {
  const parts = subject.split('/')
  if (parts.length === 4 && /^\d+$/.test(parts[2]) && /^\d+$/.test(parts[3])) {
    return `进程 PID ${parts[2]}`
  }
  return subject
}
// M33：判定详情分项解析（detail/evidence/missing/risk），替代原始 JSON 直出。
function detailInfo(f: Finding): { detail?: string; evidence?: string[]; missing?: string; risk?: string } | null {
  try {
    const d = JSON.parse(f.detail) as { detail?: string; evidence?: string[]; missing?: string; risk?: string }
    if (d && typeof d === 'object' && ('detail' in d || 'evidence' in d)) return d
    return null
  } catch { return null }
}
function bundleLabel(b: BundleSummary): string {
  return `${b.asset_id} · ${fmtLocal(b.imported_at)}（${b.id}）`
}

const current = computed(() => bundles.value.find(b => b.id === bundleId.value))
const runRows = computed(() => latestOnly.value ? latestRunFindings(findings.value, latestRunId.value) : findings.value)
const conclusions = computed(() => [...new Set(runRows.value.map(f => f.conclusion))])
const filtered = computed(() => filter.value ? runRows.value.filter(f => f.conclusion === filter.value) : runRows.value)

interface SubjectGroup { subject: string; rows: Finding[] }
interface RuleGroup { ruleId: string; rows: Finding[]; subjects: SubjectGroup[] }
const groups = computed<RuleGroup[]>(() => {
  const byRule = new Map<string, Finding[]>()
  for (const f of filtered.value) {
    const list = byRule.get(f.rule_id) ?? []
    list.push(f)
    byRule.set(f.rule_id, list)
  }
  const out: RuleGroup[] = []
  for (const [ruleId, rows] of byRule) {
    const bySubject = new Map<string, Finding[]>()
    for (const f of rows) {
      const list = bySubject.get(f.subject) ?? []
      list.push(f)
      bySubject.set(f.subject, list)
    }
    const subjects = [...bySubject.entries()]
      .map(([subject, rs]) => ({ subject, rows: rs }))
      .sort((a, b) => b.rows.length - a.rows.length)
    out.push({ ruleId, rows, subjects })
  }
  const riskRank = (id: string) => {
    const r = (rulesMap.value.get(id)?.Risk ?? '').toLowerCase()
    return r === 'high' ? 0 : r === 'medium' ? 1 : r === 'low' ? 2 : 3
  }
  return out.sort((a, b) => (riskRank(a.ruleId) - riskRank(b.ruleId)) || (b.rows.length - a.rows.length))
})

function visibleSubjects(g: RuleGroup): SubjectGroup[] {
  return g.subjects.slice(0, subjectCap.value)
}
function subjectConclusions(rows: Finding[]): string[] {
  return [...new Set(rows.map(f => f.conclusion))]
}
function toggleSubject(ruleId: string, subject: string) {
  const k = ruleId + '|' + subject
  openSubject.value = openSubject.value === k ? '' : k
}

function pretty(d: string): string {
  try { return JSON.stringify(JSON.parse(d), null, 2) } catch { return d }
}

function sameAssetBundles(f: Finding): BundleSummary[] {
  const cur = bundles.value.find(b => b.id === f.bundle_id)
  if (!cur) return []
  return bundles.value.filter(b => b.asset_id === cur.asset_id && b.id !== f.bundle_id)
}

const assetOptions = computed(() => {
  return assets.value.filter(a => latestByAsset.value.has(a.id))
})
const bundlesOfAsset = computed(() => bundles.value.filter(b => b.asset_id === assetId.value))
function latestBundleOfAsset(id: string): BundleSummary | undefined {
  return latestByAsset.value.get(id) ?? latestBundleOf(bundles.value, id)
}
async function onAssetChange() {
  try { bundles.value = await api.assetBundles(assetId.value) } catch { bundles.value = [] }
  const lb = latestBundleOfAsset(assetId.value)
  bundleId.value = lb?.id ?? ''
  await load()
}
// 怎么改：展开该类问题并打开首条问题的详情（结论卡里有修复命令与基线屏蔽）。
async function openHowTo(g: RuleGroup) {
  openRule.value = g.ruleId
  const first = g.subjects[0]?.rows[0]
  if (!first) return
  openSubject.value = g.ruleId + '|' + first.subject
  await toggle(first)
}

async function load() {
  error.value = ''; openId.value = 0; openRule.value = ''; openSubject.value = ''
  if (!bundleId.value) return
  const seq = ++loadSeq
  try { const { rows, runId } = await loadFindingsWithRun(bundleId.value); if (seq !== loadSeq) return; findings.value = rows; latestRunId.value = runId }
  catch (e) { if (seq !== loadSeq) return; error.value = e instanceof Error ? e.message : '加载失败'; findings.value = []; latestRunId.value = undefined }
}

async function toggle(f: Finding) {
  if (openId.value === f.id) { openId.value = 0; return }
  openId.value = f.id
  opMsg.value = ''; opErr.value = ''; retestBundle.value = ''
  retests.value = []; remediations.value = []
  try {
    retests.value = await api.retests(f.id)
    remediations.value = await api.remediations(f.id)
  } catch { /* 历史为空即空表 */ }
  try { fixMap.value.set(f.id, await api.fixScript(f.id)) } catch { fixMap.value.set(f.id, null) }
}

interface ExemptState {
  forId: number; loading: boolean; busy: boolean
  preview?: ExemptionPreview; baselines: BaselineRow[]
  choice: string; newId: string; reason: string; msg: string; err: string
  doneBaseline: string; reevalMsg: string
}
const exempt = ref<ExemptState | null>(null)

async function openExempt(f: Finding) {
  const st: ExemptState = {
    forId: f.id, loading: true, busy: false, baselines: [],
    choice: 'new', newId: '', reason: '', msg: '', err: '',
    doneBaseline: '', reevalMsg: '',
  }
  exempt.value = st
  try {
    const pv = await api.exemptPreview(f.id)
    st.preview = pv
    if (pv.supported) {
      const rows = await api.baselines(pv.hospital_id)
      st.baselines = rows.filter(b => b.target === pv.target)
      st.newId = 'bl-exempt-' + pv.target
      st.choice = st.baselines.length ? st.baselines[0].id : 'new'
    }
  } catch (e) { st.err = e instanceof Error ? e.message : '推导失败' }
  st.loading = false
}

async function doExempt(f: Finding) {
  const st = exempt.value
  if (!st || st.forId !== f.id) return
  st.busy = true; st.msg = ''; st.err = ''
  try {
    const res = await api.exemptFinding({
      finding_id: f.id,
      baseline_id: st.choice !== 'new' ? st.choice : undefined,
      new_baseline_id: st.choice === 'new' ? st.newId : undefined,
      reason: st.reason || undefined,
      created_by: reviewerName(),
    })
    st.doneBaseline = res.baseline_id
    st.msg = `已加入基线 ${res.baseline_id}（新增 ${res.added.length} 条${res.skipped_existing ? `，${res.skipped_existing} 条已存在` : ''}）。之后评估默认自动套用本院基线，该条不再报警。`
  } catch (e) { st.err = e instanceof Error ? e.message : '加入失败' }
  st.busy = false
}

async function reevalWithBaseline(f: Finding) {
  const st = exempt.value
  if (!st || st.forId !== f.id || !st.doneBaseline) return
  st.busy = true; st.reevalMsg = ''; st.err = ''
  try {
    const s = await api.evaluate(f.bundle_id, st.doneBaseline)
    st.reevalMsg = `重新评估完成：共 ${s.total} 条，不通过 ${s.fail} 项，落库问题 ${s.findings_stored}。新一轮已用该基线，屏蔽项不再计入。`
  } catch (e) { st.err = e instanceof Error ? e.message : '重新评估失败' }
  st.busy = false
}

async function copyFix(text: string) {
  try { await navigator.clipboard.writeText(text); copiedFix.value = true; setTimeout(() => { copiedFix.value = false }, 2000) } catch { /* 剪贴板不可用时用户可手动复制 */ }
}

async function doReview(f: Finding) {
  opMsg.value = ''; opErr.value = ''
  try {
    await api.review(f.id, {
      hospital_id: current.value?.hospital_id ?? '',
      decision: reviewForm.value.decision,
      comment: reviewForm.value.comment,
      reviewer: reviewForm.value.reviewer,
    })
    opMsg.value = '复核已提交'
    const keepRule = openRule.value, keepSubject = openSubject.value
    await load(); openId.value = f.id; openRule.value = keepRule; openSubject.value = keepSubject
  } catch (e) { opErr.value = e instanceof Error ? e.message : '复核失败' }
}

async function doRetest(f: Finding) {
  opMsg.value = ''; opErr.value = ''
  try {
    const r = await api.retest(f.id, retestBundle.value)
    opMsg.value = `复测完成：结论 ${r.conclusion}`
    retests.value = await api.retests(f.id)
  } catch (e) { opErr.value = e instanceof Error ? e.message : '复测失败' }
}

async function doRemediation(f: Finding) {
  opMsg.value = ''; opErr.value = ''
  try {
    await api.addRemediation(f.id, { ...remForm.value })
    opMsg.value = '整改已登记'
    remForm.value.action = ''
    remediations.value = await api.remediations(f.id)
  } catch (e) { opErr.value = e instanceof Error ? e.message : '登记失败' }
}

onMounted(async () => {
  try {
    assets.value = filterByHospital(await api.assets())
    try { latestByAsset.value = new Map(filterByHospital(await api.latestBundles()).map(b => [b.asset_id, b])) } catch { latestByAsset.value = new Map() }
    try {
      const rs = await api.rules()
      rulesMap.value = new Map(rs.map(r => [r.ID, r]))
    } catch { /* 无规则说明时降级为仅原始详情 */ }
    rulesReady.value = true
    // 默认该对象最新一次审计：显式指定的包优先，其次指定对象，再次首个对象。
    if (nav.bundleId) {
      try {
        const d = await api.bundleDetail(nav.bundleId)
        assetId.value = d.asset_id
        bundles.value = await api.assetBundles(assetId.value)
        bundleId.value = nav.bundleId
      } catch { /* 包不存在时回落默认对象 */ }
    }
    if (!bundleId.value) {
      if (nav.assetId && latestBundleOfAsset(nav.assetId)) {
        assetId.value = nav.assetId
        bundleId.value = latestBundleOfAsset(nav.assetId)?.id ?? ''
      } else {
        assetId.value = assetOptions.value[0]?.id ?? ''
        bundleId.value = latestBundleOfAsset(assetId.value)?.id ?? ''
      }
      if (assetId.value) {
        try { bundles.value = await api.assetBundles(assetId.value) } catch { bundles.value = [] }
      }
    }
    await load()
  } catch (e) { error.value = e instanceof Error ? e.message : '加载失败' }
})
</script>
