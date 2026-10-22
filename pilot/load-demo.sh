#!/bin/bash
# MedAudit 演示数据一键加载（M11 试点准备包；M12 适配登录鉴权）
# 用法：bash load-demo.sh [服务地址]        默认 http://127.0.0.1:8080
#   登录凭据：MEDAUDIT_USER（默认 admin）/ MEDAUDIT_PASS（未设置时交互提示输入）。
# 作用：把 demo-data/ 的真实采集事实包经公开 API 导入目标实例，依次评估、
#       跑关联分析、生成带路径/漂移章节的报告，得到一套可直接演示的工作台数据。
# 幂等：事实包按内容去重（重复导入返回 duplicate）；医院/资产重复登记会被忽略并继续。
set -u
BASE="${1:-http://127.0.0.1:8080}"
API="$BASE/api/v1"
DIR="$(cd "$(dirname "$0")" && pwd)/demo-data"
PY="$(command -v python3 || true)"
[ -n "$PY" ] || { echo "需要 python3 解析 API 响应"; exit 1; }
[ -d "$DIR" ] || { echo "未找到 demo-data 目录：$DIR"; exit 1; }

echo "== 健康检查 $BASE"
curl -fsS "$API/health" || { echo; echo "服务不可达，终止"; exit 1; }
echo

echo "== 登录（M12 起工作台接口需登录；事实包导入通道免登录，此处为登记/评估/报告步骤）"
MUSER="${MEDAUDIT_USER:-admin}"
MPASS="${MEDAUDIT_PASS:-}"
if [ -z "$MPASS" ]; then
  if [ -t 0 ]; then read -r -s -p "请输入 $MUSER 的口令: " MPASS; echo; else
    echo "未设置 MEDAUDIT_PASS 且无交互终端，终止"; exit 1; fi
fi
JAR=$(mktemp)
trap 'rm -f "$JAR"' EXIT
CODE=$(curl -sS -o /dev/null -w '%{http_code}' -c "$JAR" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$MUSER\",\"password\":\"$MPASS\"}" "$API/auth/login" || echo 000)
[ "$CODE" = 200 ] || { echo "登录失败（HTTP $CODE），终止"; exit 1; }
echo "   已登录：$MUSER"
AUTH=(-b "$JAR")

post_json() { # path body
  curl -sS "${AUTH[@]}" -X POST "$API$1" -H 'Content-Type: application/json' -d "$2"
}

echo "== 登记演示医院与资产"
post_json /hospitals '{"id":"h-demo","name":"演示医院（试点演示数据）"}' >/dev/null
post_json /assets '{"id":"db-pg-demo","hospital_id":"h-demo","kind":"db-postgres","name":"演示 PostgreSQL 16"}' >/dev/null
post_json /assets '{"id":"db-mysql-demo","hospital_id":"h-demo","kind":"db-mysql","name":"演示 MySQL 8.0"}' >/dev/null
post_json /assets '{"id":"db-oracle-demo","hospital_id":"h-demo","kind":"db-oracle","name":"演示 Oracle 19c"}' >/dev/null
post_json /assets '{"id":"os-linux-demo","hospital_id":"h-demo","kind":"os-linux","name":"演示 Linux 主机"}' >/dev/null
post_json /assets '{"id":"mw-tomcat-demo","hospital_id":"h-demo","kind":"mw-tomcat","name":"演示 Tomcat"}' >/dev/null
echo "   完成（已存在的登记会自动跳过）"

echo "== 导入事实包（顺序即时间序，漂移对比依赖此序）"
for z in demo-pg.zip demo-mysql-1.zip demo-mysql-2.zip demo-oracle-1.zip demo-oracle-2.zip demo-linux.zip demo-tomcat.zip; do
  printf '   %s -> ' "$z"
  curl -sS -X POST "$API/bundles" -H 'Content-Type: application/zip' --data-binary "@$DIR/$z" \
    | "$PY" -c 'import json,sys; d=json.load(sys.stdin); print(d.get("status","?"), d.get("bundle_id",""))'
  # 导入时间是秒级：同资产两包若同秒落库，「上一包」判定（漂移章节）会失效，故逐个间隔 2 秒。
  sleep 2
done

echo "== 导入 API 越权报告"
printf '   demo-api-report.json -> '
curl -sS -X POST "$API/api-audits" -H 'Content-Type: application/json' --data-binary "@$DIR/demo-api-report.json" \
  | "$PY" -c 'import json,sys; d=json.load(sys.stdin); print(d.get("status","stored"), d.get("report_id",""))'

echo "== 评估全部演示事实包 + 关联分析 + 生成报告"
"$PY" - "$API" "$JAR" <<'PYEOF'
import http.cookiejar, json, sys, urllib.request

API = sys.argv[1]
jar = http.cookiejar.MozillaCookieJar(sys.argv[2])
jar.load(ignore_discard=True, ignore_expires=True)
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

def call(method, path, obj=None):
    data = json.dumps(obj).encode() if obj is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={'Content-Type': 'application/json'})
    try:
        with opener.open(req) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return {'error': e.code, 'body': e.read().decode()[:160]}

bundles = [b for b in call('GET', '/bundles') if b.get('hospital_id') == 'h-demo']
bundles.sort(key=lambda b: b['imported_at'])
print(f'   演示事实包 {len(bundles)} 个')
for b in bundles:
    r = call('POST', '/evaluations', {'bundle_id': b['id']})
    print('   评估', b['id'], '->', {k: r.get(k) for k in ('total', 'fail', 'findings_stored') if k in r} or r)

ids = [b['id'] for b in bundles]
corr = call('POST', '/correlations', {'bundle_ids': ids, 'created_by': 'demo'})
print('   关联分析 ->', {k: corr.get(k) for k in ('report_id', 'path_count') if k in corr} or corr)

def report_for(asset_id, pick_last=True):
    cands = [b for b in bundles if b['asset_id'] == asset_id]
    if not cands:
        return
    b = cands[-1] if pick_last else cands[0]
    r = call('POST', '/reports', {'hospital_id': 'h-demo', 'plan_id': b['plan_id'],
                                  'bundle_id': b['id'], 'created_by': 'demo'})
    print('   报告', b['id'], '->', r.get('report_id') or r)

# 顺序讲究：关联在报告之前生成，报告快照才会带路径章节；MySQL 用第二包出漂移章节。
report_for('db-mysql-demo')
report_for('db-oracle-demo')
report_for('mw-tomcat-demo')
report_for('db-pg-demo')
report_for('os-linux-demo')
PYEOF

echo
echo "== 加载完成。演示动线（浏览器打开 $BASE，登录后查看）："
echo "   1) 工作台：类别问题卡与医院整改进度出现「演示医院」，含待整改 FAIL 与最近审计"
echo "   2) 数据库页 → PostgreSQL/MySQL：点「问题」看按规则分组的清单与整改说明"
echo "   3) 审计记录页：MySQL 第二包开「工程师详情」，看「漂移对比」（新增角色/授权/local_infile 配置）与「有效权限」（demo_via 角色派生 SUPER）"
echo "   4) 关联分析页：查看跨层提权路径（组写 Tomcat 配置→root；Oracle 角色嵌套）"
echo "   5) 报告页：按对象打开 MySQL/Oracle 报告或下载 Word（新版式：执行摘要/问题分布/路径/漂移/修复脚本章节）；业务接口页可下 API 报告 Word"
