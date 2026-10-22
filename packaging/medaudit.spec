Name:           medaudit
Version:        0.25.0
Release:        m23.1
Summary:        MedAudit 医疗权限审计平台（服务端）
License:        Proprietary
BuildArch:      x86_64
AutoReqProv:    no

%description
数据库/操作系统/中间件权限审计：采集、评估、基线豁免、整改
修复脚本与 Word 报告。安装时交互询问本站医院（或事后编辑
/etc/medaudit/medaudit.env 并 systemctl restart medaudit-server）；
Web 默认管理员 admin（首登强制改密）。工程师 CLI 为 ma 命令
（ma <功能>）。全部驱动为纯 Go 实现，零外部依赖。

%prep
# 负载由 build-packages.sh 组装在 %{_sourcedir}/rootfs

%build

%install
mkdir -p %{buildroot}
cp -a %{_sourcedir}/rootfs/. %{buildroot}/

%pre
getent group medaudit >/dev/null || groupadd --system medaudit
getent passwd medaudit >/dev/null || \
  useradd --system --gid medaudit --home-dir /var/lib/medaudit --shell /sbin/nologin medaudit
exit 0

%post
getent group medaudit >/dev/null || groupadd --system medaudit
getent passwd medaudit >/dev/null || useradd --system --gid medaudit --home-dir /var/lib/medaudit --no-create-home --shell /usr/sbin/nologin medaudit
mkdir -p /var/lib/medaudit
chown medaudit:medaudit /var/lib/medaudit
chmod 750 /var/lib/medaudit
if ! grep -q '^MEDAUDIT_EVIDENCE_KEY=..*' /etc/medaudit/medaudit.env 2>/dev/null; then
  K=$(head -c 32 /dev/urandom | base64 | tr -d '
')
  if grep -q '^#MEDAUDIT_EVIDENCE_KEY=' /etc/medaudit/medaudit.env 2>/dev/null; then
    sed -i "s|^#MEDAUDIT_EVIDENCE_KEY=.*|MEDAUDIT_EVIDENCE_KEY=$K|" /etc/medaudit/medaudit.env
  elif grep -q '^MEDAUDIT_EVIDENCE_KEY=' /etc/medaudit/medaudit.env 2>/dev/null; then
    sed -i "s|^MEDAUDIT_EVIDENCE_KEY=.*|MEDAUDIT_EVIDENCE_KEY=$K|" /etc/medaudit/medaudit.env
  else
    echo "MEDAUDIT_EVIDENCE_KEY=$K" >> /etc/medaudit/medaudit.env
  fi
fi
# 本站医院：未设置且有交互终端时询问（非交互安装跳过，不阻塞）
if grep -q '^MEDAUDIT_SITE_HOSPITAL_ID=$' /etc/medaudit/medaudit.env 2>/dev/null && ( : < /dev/tty ) 2>/dev/null; then
  printf 'medaudit: 请输入本站医院 ID（如 h-001，直接回车跳过）: ' > /dev/tty
  IFS= read -r MA_HID < /dev/tty || MA_HID=
  if [ -n "$MA_HID" ]; then
    printf 'medaudit: 请输入本站医院名称: ' > /dev/tty
    IFS= read -r MA_HNAME < /dev/tty || MA_HNAME=
    MA_HID_ESC=$(printf '%s' "$MA_HID" | sed 's|[&|\\]|\\&|g')
    sed -i "s|^MEDAUDIT_SITE_HOSPITAL_ID=$|MEDAUDIT_SITE_HOSPITAL_ID=$MA_HID_ESC|" /etc/medaudit/medaudit.env
    if [ -n "$MA_HNAME" ]; then
      MA_HNAME_ESC=$(printf '%s' "$MA_HNAME" | sed 's|[&|\\]|\\&|g')
      sed -i "s|^MEDAUDIT_SITE_HOSPITAL_NAME=$|MEDAUDIT_SITE_HOSPITAL_NAME=$MA_HNAME_ESC|" /etc/medaudit/medaudit.env
    fi
    echo "medaudit: 本站医院已设置（$MA_HID $MA_HNAME），服务启动时自动登记"
  fi
fi
chmod 640 /etc/medaudit/medaudit.env
chgrp medaudit /etc/medaudit/medaudit.env 2>/dev/null || true
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  if [ "$1" -eq 1 ]; then
    systemctl enable medaudit-server.service >/dev/null 2>&1 || true
    systemctl start medaudit-server.service >/dev/null 2>&1 || true
  else
    systemctl try-restart medaudit-server.service >/dev/null 2>&1 || true
  fi
fi
%preun
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
  systemctl --no-reload disable medaudit-server.service >/dev/null 2>&1 || true
  systemctl stop medaudit-server.service >/dev/null 2>&1 || true
fi
%postun
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ "$1" -ge 1 ] && [ -d /run/systemd/system ]; then
  systemctl try-restart medaudit-server.service >/dev/null 2>&1 || true
fi
%files
%dir %attr(0750, medaudit, medaudit) /var/lib/medaudit
%config(noreplace) /etc/medaudit/medaudit.env
/lib/systemd/system/medaudit-server.service
/opt/medaudit
/usr/bin/ma

%changelog
* Thu Oct 22 2026 MedAudit <dengweiquan@gmail.com> - 0.25.0-m23.1
- 首个系统包版本：0.25.0-m23（ma 命令族、基线一键豁免、本地时区显示）
