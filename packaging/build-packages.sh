#!/bin/bash
# 组装 rootfs 并构建 .deb 与 .rpm。
# 用法: bash packaging/build-packages.sh [产物目录]
# 前置: package.sh 已产出 /tmp/medaudit-dist/medaudit-0.25.0-m23 负载树。
set -e
cd "$(dirname "$0")/.."          # 仓库根 /kf/medaudit
PKGSRC=packaging
SRC=/tmp/medaudit-dist/medaudit-0.25.0-m23
OUT="${1:-/tmp/medaudit-dist}"
mkdir -p "$OUT"
WORK=$(mktemp -d)
ROOTFS=$WORK/rootfs
trap 'rm -rf "$WORK"' EXIT

[ -d "$SRC/bin" ] || { echo "负载树不存在：先跑 bash package.sh 0.25.0-m23"; exit 1; }

echo "=== 组装 rootfs ==="
mkdir -p "$ROOTFS"/{opt/medaudit,usr/bin,etc/medaudit,lib/systemd/system,var/lib/medaudit}
cp -a "$SRC"/bin "$SRC"/web "$SRC"/migrations-sqlite "$SRC"/rulesets "$SRC"/queries "$SRC"/docs "$SRC"/pilot "$ROOTFS/opt/medaudit/"
cp "$SRC/install.sh" "$ROOTFS/opt/medaudit/" 2>/dev/null || true
cp "$PKGSRC/medaudit-server.service" "$ROOTFS/lib/systemd/system/"
cp "$PKGSRC/medaudit.env" "$ROOTFS/etc/medaudit/"
ln -sf "/opt/medaudit/bin/ma" "$ROOTFS/usr/bin/ma"
find "$ROOTFS/opt/medaudit/bin" -type f -exec chmod 755 {} +

echo "=== 构建 .deb ==="
DEBSTAGE=$WORK/debstage
cp -a "$ROOTFS" "$DEBSTAGE"
mkdir -p "$DEBSTAGE/DEBIAN"
cp "$PKGSRC"/deb/control "$PKGSRC"/deb/postinst "$PKGSRC"/deb/prerm "$PKGSRC"/deb/postrm "$DEBSTAGE/DEBIAN/"
chmod 755 "$DEBSTAGE/DEBIAN/"postinst "$DEBSTAGE/DEBIAN/"prerm "$DEBSTAGE/DEBIAN/"postrm
echo "/etc/medaudit/medaudit.env" > "$DEBSTAGE/DEBIAN/conffiles"
dpkg-deb --build "$DEBSTAGE" "$OUT/medaudit_0.25.0+m23-1_amd64.deb"

echo "=== 构建 .rpm ==="
RPMWORK=$WORK/rpmbuild
mkdir -p "$RPMWORK"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp -a "$ROOTFS" "$RPMWORK/SOURCES/rootfs"
cp "$PKGSRC/medaudit.spec" "$RPMWORK/SPECS/"
rpmbuild -bb --define "_topdir $RPMWORK" "$RPMWORK/SPECS/medaudit.spec"
cp "$RPMWORK"/RPMS/x86_64/*.rpm "$OUT/"

ls -lh "$OUT"/medaudit_0.25.0+m23-1_amd64.deb "$OUT"/medaudit-0.25.0-m23.1.x86_64.rpm
echo "=== 完成 ==="
