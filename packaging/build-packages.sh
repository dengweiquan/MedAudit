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
# 目标架构：GOARCH 缺省 amd64；GOARCH=arm64 出 arm64 包
# （deb 架构段 arm64、rpm 架构段 aarch64，鲲鹏/飞腾）。
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
# 目标架构（与 package.sh 同口径，M26）：映射 deb/rpm 架构段。
TARCH="${GOARCH:-amd64}"
case "$TARCH" in
  amd64) DEBARCH=amd64; RPMARCH=x86_64 ;;
  arm64) DEBARCH=arm64; RPMARCH=aarch64 ;;
  *) echo "不支持的 GOARCH: $TARCH（仅 amd64 / arm64）"; exit 1 ;;
esac
SRC=/tmp/medaudit-dist/medaudit-$VER
OUT="${1:-/tmp/medaudit-dist}"
mkdir -p "$OUT"
WORK=$(mktemp -d)
ROOTFS=$WORK/rootfs
trap 'rm -rf "$WORK"' EXIT

[ -d "$SRC/bin" ] || { echo "负载树不存在：先跑 bash package.sh $VER"; exit 1; }

# 架构一致性护栏：负载树里的服务端二进制必须与目标架构相符，
# 防止把 amd64 二进制打进 arm64 包（或反之）。
if command -v file >/dev/null; then
  case "$TARCH" in
    amd64) file "$SRC/bin/medaudit-server" | grep -q 'x86-64' || { echo "负载树二进制不是 x86-64：请先以缺省架构跑 bash package.sh $VER"; exit 1; } ;;
    arm64) file "$SRC/bin/medaudit-server" | grep -q 'ARM aarch64' || { echo "负载树二进制不是 arm64：请先跑 GOARCH=arm64 bash package.sh $VER"; exit 1; } ;;
  esac
fi

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
sed -i -e "s/@DEB_VERSION@/$DEBVER/" -e "s/@DEB_ARCH@/$DEBARCH/" "$DEBSTAGE/DEBIAN/control"
chmod 755 "$DEBSTAGE/DEBIAN/"postinst "$DEBSTAGE/DEBIAN/"prerm "$DEBSTAGE/DEBIAN/"postrm
echo "/etc/medaudit/medaudit.env" > "$DEBSTAGE/DEBIAN/conffiles"
dpkg-deb --build "$DEBSTAGE" "$OUT/medaudit_${DEBVER}_${DEBARCH}.deb"

echo "=== 构建 .rpm ==="
RPMWORK=$WORK/rpmbuild
mkdir -p "$RPMWORK"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp -a "$ROOTFS" "$RPMWORK/SOURCES/rootfs"
cp "$PKGSRC/medaudit.spec" "$RPMWORK/SPECS/"
sed -i -e "s/@RPM_VERSION@/$BASE/" -e "s/@RPM_RELEASE@/$RPMREL/" "$RPMWORK/SPECS/medaudit.spec"
# 跨架构构建时本机 strip/objdump 认不出目标 ELF（brp-strip 会让
# %install 失败），以 /bin/true 顶替这两个后处理工具——Go 二进制
# 本就不需要 rpm 再 strip。本机架构构建不加此定义，行为不变。
HOSTARCH=$(go env GOHOSTARCH 2>/dev/null || echo amd64)
STRIP_DEFINES=()
if [ "$TARCH" != "$HOSTARCH" ]; then
  STRIP_DEFINES=(--define "__strip /bin/true" --define "__objdump /bin/true")
fi
rpmbuild -bb --target "${RPMARCH}-linux" --define "_topdir $RPMWORK" "${STRIP_DEFINES[@]}" "$RPMWORK/SPECS/medaudit.spec"
# 架构核验：产物 rpm 的 %{ARCH} 必须与目标架构一致（spec 不写
# BuildArch，架构由 --target 决定，在此核验兜底）。
BUILT_RPM=$(ls "$RPMWORK"/RPMS/${RPMARCH}/*.rpm)
rpm -qp --qf '%{ARCH}' "$BUILT_RPM" | grep -qx "$RPMARCH" || { echo "rpm 架构不符：期望 $RPMARCH，实际 $(rpm -qp --qf '%{ARCH}' "$BUILT_RPM")"; exit 1; }
cp "$RPMWORK"/RPMS/${RPMARCH}/*.rpm "$OUT/"

ls -lh "$OUT/medaudit_${DEBVER}_${DEBARCH}.deb" "$OUT/medaudit-${BASE}-${RPMREL}.${RPMARCH}.rpm"
echo "=== 完成 ==="
