#!/bin/bash
# MedAudit 部署后自检（试点准备包现行版；M12 适配登录鉴权，M18 刷新检查面）
# 用法：bash smoke-test.sh [服务地址]     默认 http://127.0.0.1:8080
#   已启用登录鉴权后，建议提供凭据做全量内容校验：
#   MEDAUDIT_USER=admin MEDAUDIT_PASS=<口令> bash smoke-test.sh
#   不提供凭据时，受保护接口返回 401 视为「鉴权生效」通过（仅跳过内容校验）。
# 只读检查，不写任何数据。全部通过退出码 0，任一失败退出码 1。
set -u
BASE="${1:-http://127.0.0.1:8080}"
API="$BASE/api/v1"
FAIL=0
AUTH=()
LOGGED_IN=0
JAR=$(mktemp)
trap 'rm -f "$JAR" /tmp/medaudit-smoke-health.json' EXIT

check() { # 名称 期望 说明 实际
  if [ "$2" = "$4" ]; then echo "PASS  $1  $3"; else echo "FAIL  $1  $3（实际：$4）"; FAIL=1; fi
}

CODE=$(curl -s -o /tmp/medaudit-smoke-health.json -w '%{http_code}' "$API/health" 2>/dev/null || echo 000)
check "健康端点" 200 "GET /api/v1/health" "$CODE"
if [ "$CODE" = 200 ]; then
  grep -q '"status":"ok"' /tmp/medaudit-smoke-health.json \
    && echo "PASS  健康状态  $(sed -n 's/.*\"version\":\"\([^\"]*\)\".*/版本 \1/p' /tmp/medaudit-smoke-health.json)" \
    || { echo "FAIL  健康状态  status 非 ok"; FAIL=1; }
fi

CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/" 2>/dev/null || echo 000)
check "Web 页面" 200 "GET /" "$CODE"

# 登录鉴权：未登录访问受保护接口应得 401；提供凭据时先登录
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$API/bundles" 2>/dev/null || echo 000)
check "鉴权拦截" 401 "未登录 GET /api/v1/bundles 应被拦截" "$CODE"

if [ -n "${MEDAUDIT_USER:-}" ] && [ -n "${MEDAUDIT_PASS:-}" ]; then
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$MEDAUDIT_USER\",\"password\":\"$MEDAUDIT_PASS\"}" "$API/auth/login" 2>/dev/null || echo 000)
  check "登录" 200 "POST /api/v1/auth/login（$MEDAUDIT_USER）" "$CODE"
  [ "$CODE" = 200 ] && { LOGGED_IN=1; AUTH=(-b "$JAR"); }
else
  echo "NOTE  未提供 MEDAUDIT_USER/MEDAUDIT_PASS，跳过登录后内容校验（设置环境变量可启用）"
fi

if [ "$LOGGED_IN" = 1 ]; then
  RULES=$(curl -s "${AUTH[@]}" "$API/rules" 2>/dev/null | grep -oiE '"id"\s*:' | wc -l)
  if [ "${RULES:-0}" -ge 59 ]; then echo "PASS  规则库  共 $RULES 条"; else echo "FAIL  规则库  仅 ${RULES:-0} 条"; FAIL=1; fi
  for p in bundles hospitals assets summary/hospitals correlations api-audits site rule-toggles; do
    CODE=$(curl -s "${AUTH[@]}" -o /dev/null -w '%{http_code}' "$API/$p" 2>/dev/null || echo 000)
    check "接口 $p" 200 "GET /api/v1/$p" "$CODE"
  done
fi

echo
if [ "$FAIL" = 0 ]; then echo "自检结论：全部通过，服务可用于试点。"; else echo "自检结论：存在失败项，请先处理再开展试点。"; fi
exit $FAIL
