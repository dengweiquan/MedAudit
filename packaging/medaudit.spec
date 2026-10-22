Name:           medaudit
Version:        0.25.0
Release:        m23.1
Summary:        MedAudit 医疗权限审计平台（服务端）
License:        Proprietary
BuildArch:      x86_64
AutoReqProv:    no

%description
数据库/操作系统/中间件权限审计：采集、评估、基线豁免、整改
修复脚本与 Word 报告。安装后编辑 /etc/medaudit/medaudit.env
填本站医院并 systemctl restart medaudit-server；Web 默认
管理员 admin（首登强制改密）。工程师 CLI 为 ma 命令族。
Oracle 采集另需 Oracle Instant Client（见 medaudit.env 注释）。

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
/usr/bin/malogin
/usr/bin/malogout
/usr/bin/mawhoami
/usr/bin/mause
/usr/bin/masite
/usr/bin/mauserls
/usr/bin/mauseradd
/usr/bin/mauseron
/usr/bin/mauseroff
/usr/bin/mauserpw
/usr/bin/maassetls
/usr/bin/maassetadd
/usr/bin/maassetshow
/usr/bin/maassetmod
/usr/bin/maassetrm
/usr/bin/maaudit
/usr/bin/maeval
/usr/bin/maoffeval
/usr/bin/mabundlels
/usr/bin/mabundlein
/usr/bin/mabundleshow
/usr/bin/mabundledrift
/usr/bin/mabundleeff
/usr/bin/mafind
/usr/bin/mareport
/usr/bin/mareportls
/usr/bin/mareportshow
/usr/bin/mareportfix
/usr/bin/mabasels
/usr/bin/mabaseshow
/usr/bin/mabaseadd
/usr/bin/mabasediff
/usr/bin/mabaseexempt
/usr/bin/marulels
/usr/bin/maruleoff
/usr/bin/maruleon
/usr/bin/macorr
/usr/bin/masum
/usr/bin/masrv
/usr/bin/masrvbak

%changelog
* Thu Oct 22 2026 MedAudit <dengweiquan@gmail.com> - 0.25.0-m23.1
- 首个系统包版本：0.25.0-m23（ma 命令族、基线一键豁免、本地时区显示）
