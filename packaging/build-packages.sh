#!/bin/bash
# 组装 rootfs 并构建 .deb 与 .rpm。
# 用法: bash packaging/build-packages.sh [产物目录] <版本>
#   版本是唯一入口（如 0.26.0-m25），与 package.sh 的入参同值，
#   也可经环境变量 VERSION 传入。前置: package.sh 已产出对应负载树。
#
# 版本派生规则（本脚本是唯一实现处，control/spec 只写占位符）：
#   产品版本 X.Y.Z-mN → 负载树 medaudit-X.Y.Z-mN
#   deb: Version = X.Y.Z+mN-1，文件名 medaudit_<Version>_amd64.deb
#   rpm: Version = X.Y.Z，Release = mN.1，
#        文件名 medaudit-X.Y.Z-mN.1.x86_64.rpm
#   无 -mN 后缀时：deb Version = X.Y.Z-1，rpm Release = 1。
set -e
cd "$(dirname "$0")/.."          # 仓库根
PKGSRC=packaging
VER="${2:-${VERSION:-}}"
[ -n "$VER" ] || { echo "用法: bash packaging/build-packages.sh [产物目录] <版本，如 0.26.0-m25>"; exit 1; }
BASE="${VER%%-*}"
if [ "$VER" = "$BASE" ]; then
  DEBVER="${BASE}-1"
  RPMREL="1"
else
  SUFFIX="${VER#*-}"
  DEBVER="${BASE}+${SUFFIX}-1"
  RPMREL="${SUFFIX}.1"
fi
SRC=/tmp/medaudit-dist/medaudit-$VER
OUT="${1:-/tmp/medaudit-dist}"
mkdir -p "$OUT"
WORK=$(mktemp -d)
ROOTFS=$WORK/rootfs
trap 'rm -rf "$WORK"' EXIT

[ -d "$SRC/bin" ] || { echo "负载树不存在：先跑 bash package.sh $VER"; exit 1; }

echo "=== 组装 rootfs（版本 $VER）==="
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
sed -i "s/@DEB_VERSION@/$DEBVER/" "$DEBSTAGE/DEBIAN/control"
chmod 755 "$DEBSTAGE/DEBIAN/"postinst "$DEBSTAGE/DEBIAN/"prerm "$DEBSTAGE/DEBIAN/"postrm
echo "/etc/medaudit/medaudit.env" > "$DEBSTAGE/DEBIAN/conffiles"
dpkg-deb --build "$DEBSTAGE" "$OUT/medaudit_${DEBVER}_amd64.deb"

echo "=== 构建 .rpm ==="
RPMWORK=$WORK/rpmbuild
mkdir -p "$RPMWORK"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp -a "$ROOTFS" "$RPMWORK/SOURCES/rootfs"
cp "$PKGSRC/medaudit.spec" "$RPMWORK/SPECS/"
sed -i -e "s/@RPM_VERSION@/$BASE/" -e "s/@RPM_RELEASE@/$RPMREL/" "$RPMWORK/SPECS/medaudit.spec"
rpmbuild -bb --define "_topdir $RPMWORK" "$RPMWORK/SPECS/medaudit.spec"
cp "$RPMWORK"/RPMS/x86_64/*.rpm "$OUT/"

ls -lh "$OUT/medaudit_${DEBVER}_amd64.deb" "$OUT/medaudit-${BASE}-${RPMREL}.x86_64.rpm"
echo "=== 完成 ==="
