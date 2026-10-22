#!/bin/bash
# MedAudit V1 安装包打包脚本
# 用法: bash package.sh <版本号，如 0.26.0-m25>（必填，与 build-packages.sh 同值）
set -e
cd "$(dirname "$0")"
VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "用法: bash package.sh <版本号，如 0.26.0-m25>"; exit 1; }
# 版本一致性护栏：三处程序版本常量必须与打包版本一致，防止包名与
# 程序自报版本不符（常量仍是版本源头，本脚本只做校验、不注入）。
for f in cmd/medaudit-server/main.go cmd/ma/main.go cmd/medaudit-collector/main.go; do
  grep -q "const version = \"$VERSION\"" "$f" || { echo "版本不一致：$f 的 const version 不是 $VERSION，请先同步三处版本常量"; exit 1; }
done
DIST="/tmp/medaudit-dist"
PKG="$DIST/medaudit-$VERSION"

echo "=== 打包 MedAudit $VERSION ==="
rm -rf "$DIST"
mkdir -p "$PKG"/{bin,migrations-sqlite,rulesets,queries,web,docs,pilot}

echo "--- 构建 Linux 二进制 ---"
go build -o "$PKG/bin/medaudit-server" ./cmd/medaudit-server
go build -o "$PKG/bin/medaudit-collector" ./cmd/medaudit-collector
go build -o "$PKG/bin/medaudit-fixture" ./cmd/medaudit-fixture

echo "--- 交叉编译 Windows 采集器 ---"
GOOS=windows go build -o "$PKG/bin/medaudit-collector.exe" ./cmd/medaudit-collector

echo "--- 工程师 CLI（Linux + Windows）---"
go build -o "$PKG/bin/ma" ./cmd/ma
GOOS=windows go build -o "$PKG/bin/ma.exe" ./cmd/ma

echo "--- 复制前端/迁移/规则/SQL 模板 ---"
cp -r web/dist "$PKG/web/"
cp internal/platform/sqlite_migrations/*.sql "$PKG/migrations-sqlite/"
cp rulesets/*.yaml "$PKG/rulesets/"
cp -r queries "$PKG/"

echo "--- 文档 ---"
cp docs/*.md "$PKG/docs/" 2>/dev/null || true
cp -r pilot/* "$PKG/pilot/" 2>/dev/null || true
cp PROTOCOL.md "$PKG/docs/" 2>/dev/null || true

echo "--- 安装脚本 ---"
cat > "$PKG/install.sh" << 'EOF'
#!/bin/bash
# MedAudit 服务端安装脚本（需 root）
set -e
INSTALL_DIR="/opt/medaudit"
echo "安装到 $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
cp -a bin "$INSTALL_DIR/"
cp -r migrations-sqlite rulesets queries web docs "$INSTALL_DIR/"
mkdir -p "$INSTALL_DIR/data"
chown medaudit:medaudit "$INSTALL_DIR/data" 2>/dev/null || true
cat > /etc/systemd/system/medaudit-server.service << 'SVC'
[Unit]
Description=MedAudit Server
After=network.target
[Service]
Type=simple
User=medaudit
EnvironmentFile=-/etc/medaudit/evidence.env
Environment=MEDAUDIT_PLATFORM_DB=/opt/medaudit/data/medaudit.db
Environment=MEDAUDIT_COLLECTOR_BIN=/opt/medaudit/bin/medaudit-collector
Environment=MEDAUDIT_COLLECTOR_WIN_BIN=/opt/medaudit/bin/medaudit-collector.exe
WorkingDirectory=/opt/medaudit
ExecStart=/opt/medaudit/bin/medaudit-server --web-dir /opt/medaudit/web/dist --addr 127.0.0.1:8080
Restart=on-failure
[Install]
WantedBy=multi-user.target
SVC
useradd -r -s /bin/false medaudit 2>/dev/null || true
mkdir -p /etc/medaudit
echo "平台库为本地 SQLite 文件（/opt/medaudit/data/medaudit.db），首次启动自动建库迁移，无需单独安装数据库。"
echo "如需证据加密：创建 /etc/medaudit/evidence.env（600），写入 MEDAUDIT_EVIDENCE_KEY=<base64 32B> 与 MEDAUDIT_EVIDENCE_KEY_VERSION=1"
echo "然后: systemctl daemon-reload && systemctl enable --now medaudit-server"
EOF
chmod +x "$PKG/install.sh"

echo "--- 打包 ---"
cd "$DIST"
tar czf "medaudit-$VERSION.tar.gz" "medaudit-$VERSION"
ls -lh "medaudit-$VERSION.tar.gz"
echo "=== 完成 ==="
