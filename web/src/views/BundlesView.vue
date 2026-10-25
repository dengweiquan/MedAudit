<template>
  <div class="card">
    <h2>上传事实包</h2>
    <div class="inline-form">
      <input type="file" accept=".zip" @change="onFile" />
      <button class="btn primary" :disabled="!file || uploading" @click="upload">上传</button>
      <span class="msg" v-if="uploadMsg">{{ uploadMsg }}</span>
      <span class="msg err" v-if="uploadErr">{{ uploadErr }}</span>
    </div>
    <div class="todo">工程师回传通道：选择采集器产出的 bundle zip；重复上传同一包会提示 duplicate，不会重复入库。上传后在下方记录的「工程师详情」里点「评估」生成问题。</div>
  </div>

  <div class="card">
    <h2>审计记录（按对象）</h2>
    <div v-if="error" class="error">{{ error }}</div>
    <div v-else-if="!assetGroups.length" class="empty">暂无审计记录。先在类别页对对象开始审计，或在上方上传事实包。</div>
    <template v-for="g in assetGroups" :key="g.assetId">
      <h3 style="margin:14px 0 6px">{{ g.name }} <span class="todo">{{ g.assetId }} · {{ g.hospital }} · 共 {{ g.bundles.length }} 次审计</span></h3>
      <table>
        <thead><tr><th>审计时间</th><th>执行</th><th>事实</th><th>问题（FAIL）</th><th>操作</th></tr></thead>
        <tbody>
          <template v-for="b in g.bundles" :key="b.id">
            <tr :class="{ selected: explorerId === b.id || effectiveId === b.id }">
              <td>{{ fmtLocal(b.imported_at) }}<div class="todo">{{ b.id }}</div></td>
              <td><span class="concl" :class="b.execution === 'COMPLETE' ? 'c-PASS' : 'c-UNKNOWN'">{{ b.execution }}</span></td>
              <td>{{ b.fact_count }}</td>
              <td><span v-if="(failOf(b.id) ?? 0) > 0" class="concl c-FAIL">{{ failOf(b.id) }}</span><span v-else-if="failOf(b.id) === 0">0</span><span v-else>—</span></td>
              <td>
                <div class="row-actions">
                  <button class="btn small primary" @click="goto('findings', b.id)">问题</button>
                  <button class="btn small" @click="engId = engId === b.id ? '' : b.id">工程师详情</button>
                </div>
              </td>
            </tr>
            <tr v-if="engId === b.id">
              <td colspan="5">
                <div class="todo" style="margin-bottom:6px">适配器 {{ b.adapter }} · 收据 {{ b.receipt_count }} 张 · 计划 {{ b.plan_id }}</div>
                <div class="row-actions">
                  <select v-model="selectedBaseline[b.id]" title="评估基线（可选）" style="max-width:150px">
                    <option value="">自动套用本院基线（默认）</option>
                    <option v-for="bl in baselinesMap[b.hospital_id] || []" :key="bl.id" :value="bl.id">{{ bl.id }}</option>
                    <option value="__bare">裸评（不套用基线）</option>
                  </select>
                  <button class="btn small" @click="evaluate(b)" :disabled="evaluating === b.id">评估</button>
                  <button class="btn small" @click="toggleExplorer(b.id)">事实明细</button>
                  <button class="btn small" @click="toggleEffective(b.id)">有效权限</button>
                  <button class="btn small" v-if="prevBundleOf(b)" @click="toggleDrift(b)">漂移对比</button>
                  <a class="btn small" :href="api.evidenceUrl(b.id)" download>证据下载</a>
                </div>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </template>
    <div class="msg" v-if="evalMsg">{{ evalMsg }}</div>
    <div class="msg err" v-if="evalErr">{{ evalErr }}</div>
  </div>

  <div class="card" v-if="effectiveId">
    <h2>有效权限（传递闭包）· {{ effectiveId }}</h2>
    <div class="todo" style="margin-top:0">经角色/组传递后每个主体实际持有的角色与权限；「经…派生」的权限是单看直接授权看不见的部分。</div>
    <div v-if="effectiveError" class="error">{{ effectiveError }}</div>
    <table v-else-if="effectiveRows.length">
      <thead><tr><th>主体</th><th>类型</th><th>持有角色（路径）</th><th>派生权限</th></tr></thead>
      <tbody>
        <tr v-for="e in effectiveRows" :key="e.subject">
          <td>{{ e.subject }}</td>
          <td>{{ e.is_role ? '角色' : '主体' }}</td>
          <td class="detail-cell">{{ e.roles.length ? e.roles.map(r => r.path.join(' → ')).join('；') : '—' }}</td>
          <td class="detail-cell">{{ derivedText(e) }}</td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty">该事实包没有角色边或授权事实。</div>
  </div>

  <div class="card" v-if="drift">
    <h2>漂移对比 · {{ drift.compare_id }} 相对 {{ drift.base_id }}</h2>
    <p class="todo" style="margin-top:0">
      新增 {{ drift.added_total }} 项、消失 {{ drift.removed_total }} 项；
      其中 <b style="color:#b91c1c">新增授权/角色关系 {{ drift.attention }} 项</b>需重点关注。
      （仅比权限语义稳定的事实：授权、角色、账号、配置、文件权限；进程等瞬时事实不入对比。）
    </p>
    <div v-if="driftError" class="error">{{ driftError }}</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
      <div>
        <h3 style="margin:4px 0">新增（{{ drift.added.length }}）</h3>
        <table v-if="drift.added.length">
          <tbody>
            <tr v-for="(it, i) in drift.added" :key="i">
              <td><span class="concl c-FAIL">{{ it.category }}</span></td>
              <td>{{ it.subject }}<div class="todo">{{ it.detail }}</div></td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">无新增。</div>
      </div>
      <div>
        <h3 style="margin:4px 0">消失（{{ drift.removed.length }}）</h3>
        <table v-if="drift.removed.length">
          <tbody>
            <tr v-for="(it, i) in drift.removed" :key="i">
              <td><span class="concl c-PASS">{{ it.category }}</span></td>
              <td>{{ it.subject }}<div class="todo">{{ it.detail }}</div></td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">无消失。</div>
      </div>
    </div>
  </div>

  <div class="card" v-if="explorerId">
    <h2>事实明细（{{ explorerId }}）</h2>
    <div class="chips">
      <button class="chip" :class="{ active: kind === '' }" @click="setKind('')">全部 {{ totalAll }}</button>
      <button v-for="(n, k) in counts" :key="k" class="chip" :class="{ active: kind === k }" @click="setKind(k as string)">{{ k }} {{ n }}</button>
    </div>
    <div v-if="factsError" class="error">{{ factsError }}</div>
    <table v-else-if="facts.length">
      <thead><tr><th>类型</th><th>主体</th><th>状态</th><th>来源</th><th>属性</th></tr></thead>
      <tbody>
        <tr v-for="f in facts" :key="f.fact_id">
          <td>{{ f.kind }}</td><td>{{ f.subject }}</td><td>{{ f.status }}</td><td>{{ f.source }}</td>
          <td class="detail-cell" :title="attrText(f)">{{ attrText(f) }}</td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty">该筛选下暂无事实。</div>
    <div class="pager">
      <button class="btn small" :disabled="offset === 0" @click="page(-1)">上一页</button>
      <span>{{ pageInfo }}</span>
      <button class="btn small" :disabled="offset + facts.length >= total" @click="page(1)">下一页</button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, type Asset, type BaselineRow, type BundleSummary, type DriftReport, type EffectiveEntry, type Fact } from '../api'
import { goto, filterByHospital } from '../store'
import { latestFail, fmtLocal} from '../util'

const bundles = ref<BundleSummary[]>([])
const assets = ref<Asset[]>([])
const failMap = ref<Map<string, number>>(new Map())
const engId = ref('')
const error = ref('')
const file = ref<File | null>(null)
const uploading = ref(false)
const uploadMsg = ref('')
const uploadErr = ref('')
const evaluating = ref('')
const evalMsg = ref('')
const evalErr = ref('')

const explorerId = ref('')
const effectiveId = ref('')
const drift = ref<DriftReport | null>(null)
const driftError = ref('')
const effectiveRows = ref<EffectiveEntry[]>([])
const effectiveError = ref('')
const kind = ref('')
const counts = ref<Record<string, number>>({})
const totalAll = ref(0)
const total = ref(0)
const facts = ref<Fact[]>([])
const factsError = ref('')
const offset = ref(0)
const LIMIT = 100

interface AssetGroup { assetId: string; name: string; hospital: string; bundles: BundleSummary[] }
const assetGroups = computed<AssetGroup[]>(() => {
  const byAsset = new Map<string, BundleSummary[]>()
  for (const b of bundles.value) {
    const list = byAsset.get(b.asset_id) ?? []
    list.push(b)
    byAsset.set(b.asset_id, list)
  }
  const groups: AssetGroup[] = []
  for (const [assetId, list] of byAsset) {
    const a = assets.value.find(x => x.id === assetId)
    groups.push({
      assetId,
      name: a?.name ?? assetId,
      hospital: list[0]?.hospital_id ?? a?.hospital_id ?? '',
      bundles: [...list].sort((x, y) => y.imported_at.localeCompare(x.imported_at)),
    })
  }
  // 最近有审计的对象排前面
  return groups.sort((x, y) => (y.bundles[0]?.imported_at ?? '').localeCompare(x.bundles[0]?.imported_at ?? ''))
})

function failOf(id: string): number | undefined { return failMap.value.get(id) }

const pageInfo = computed(() =>
  total.value ? `${offset.value + 1}–${offset.value + facts.value.length} / ${total.value}` : '0')

function onFile(e: Event) {
  const t = e.target as HTMLInputElement
  file.value = t.files && t.files.length ? t.files[0] : null
}

const baselinesMap = ref<Record<string, BaselineRow[]>>({})
const selectedBaseline = ref<Record<string, string>>({})

async function load() {
  try {
    bundles.value = filterByHospital(await api.bundles())
    try { assets.value = filterByHospital(await api.assets()) } catch { assets.value = [] }
    const hospitals = [...new Set(bundles.value.map(b => b.hospital_id))]
    for (const h of hospitals) {
      if (!(h in baselinesMap.value)) {
        try { baselinesMap.value[h] = await api.baselines(h) } catch { baselinesMap.value[h] = [] }
      }
    }
    const m = new Map<string, number>()
    for (const b of bundles.value) {
      try { m.set(b.id, latestFail(await api.findings(b.id)).length) } catch { /* 未评估包 */ }
    }
    failMap.value = m
  }
  catch (e) { error.value = e instanceof Error ? e.message : '加载失败' }
}

async function upload() {
  if (!file.value) return
  uploading.value = true; uploadMsg.value = ''; uploadErr.value = ''
  try {
    const r = await api.uploadBundle(file.value)
    uploadMsg.value = r.status === 'duplicate'
      ? `${r.bundle_id} 已存在（duplicate），未重复入库`
      : `已导入 ${r.bundle_id}：${r.facts} 条事实 / ${r.receipts} 张收据`
    await load()
  } catch (e) {
    uploadErr.value = e instanceof Error ? e.message : '上传失败'
  } finally { uploading.value = false }
}

async function evaluate(b: BundleSummary) {
  evaluating.value = b.id; evalMsg.value = ''; evalErr.value = ''
  try {
    const bl = selectedBaseline.value[b.id] || ''
    const bare = bl === '__bare'
    const s = await api.evaluate(b.id, bare ? '' : bl, bare)
    const mode = s.baseline_mode === 'auto'
      ? `（已自动套用本院基线${s.baselines_applied?.length ? '：' + s.baselines_applied.join('、') : '，本院暂无基线'}）`
      : s.baseline_mode === 'bare' ? '（裸评）' : bl ? `（基线 ${bl}）` : ''
    evalMsg.value = `${b.id} 评估完成${mode}：${s.total} 条结果，FAIL ${s.fail}，落库问题 ${s.findings_stored}`
    failMap.value.set(b.id, s.fail)
  } catch (e) {
    evalErr.value = e instanceof Error ? e.message : '评估失败'
  } finally { evaluating.value = '' }
}

async function toggleEffective(id: string) {
  if (effectiveId.value === id) { effectiveId.value = ''; return }
  effectiveId.value = id
  effectiveError.value = ''
  try { effectiveRows.value = await api.bundleEffective(id) }
  catch (e) { effectiveError.value = e instanceof Error ? e.message : '有效权限加载失败' }
}

function prevBundleOf(b: BundleSummary): BundleSummary | undefined {
  return bundles.value
    .filter(x => x.id !== b.id && x.asset_id === b.asset_id && x.adapter === b.adapter && x.imported_at < b.imported_at)
    .sort((a, c) => c.imported_at.localeCompare(a.imported_at))[0]
}

async function toggleDrift(b: BundleSummary) {
  if (drift.value && drift.value.compare_id === b.id) { drift.value = null; return }
  const prev = prevBundleOf(b)
  if (!prev) return
  driftError.value = ''
  try { drift.value = await api.bundleDrift(b.id, prev.id) }
  catch (e) { driftError.value = e instanceof Error ? e.message : '漂移对比失败' }
}

function derivedText(e: EffectiveEntry): string {
  const d = e.privileges.filter(p => !p.direct)
  if (!d.length) return '—'
  return d.slice(0, 8).map(p => `${p.privilege}${p.scope ? '@' + p.scope : ''}`).join('、') + (d.length > 8 ? ` 等 ${d.length} 项` : '')
}

async function toggleExplorer(id: string) {
  if (explorerId.value === id) { explorerId.value = ''; return }
  explorerId.value = id
  kind.value = ''; offset.value = 0
  await loadFacts()
}

async function loadFacts() {
  factsError.value = ''
  try {
    const p = await api.bundleFacts(explorerId.value, kind.value, offset.value, LIMIT)
    facts.value = p.facts
    total.value = p.total
    counts.value = p.counts_by_kind
    totalAll.value = Object.values(p.counts_by_kind).reduce((a, n) => a + n, 0)
  } catch (e) {
    factsError.value = e instanceof Error ? e.message : '事实加载失败'
  }
}

function setKind(k: string) { kind.value = k; offset.value = 0; loadFacts() }
function page(d: number) { offset.value = Math.max(0, offset.value + d * LIMIT); loadFacts() }
function attrText(f: Fact): string {
  const parts: string[] = []
  if (f.attributes) for (const [k, v] of Object.entries(f.attributes)) parts.push(`${k}=${v}`)
  if (f.permission_path && f.permission_path.length) parts.push(`path: ${f.permission_path.join(' → ')}`)
  if (f.scope) parts.push(`scope=${f.scope}`)
  return parts.join('; ')
}

onMounted(load)
</script>
