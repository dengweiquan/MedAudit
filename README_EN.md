# MedAudit

[中文](README.md)

A **permission-audit platform for healthcare IT**: read-only permission
collection and rule evaluation for databases, operating systems,
middleware, and HTTP APIs. It answers "who holds which permissions,
which of them are problems, and how to fix them", and closes the loop —
audit → report → remediate → re-audit — with professional Word reports.

- **`medaudit-server`**: the audit platform for a single hospital site
  (Web workbench, report generation, rule/baseline management). One
  deployment serves exactly one hospital.
- **`medaudit-collector`**: collects permission facts on the target side
  or remotely, strictly read-only, and packs them into verifiable fact
  bundles.
- **`ma` command family**: an HP-UX LVM-style engineer CLI — one command
  per task (`ma audit`, `ma find`, `ma report`, `ma basels`, …).

## Quick start

```
# 1. Install (Debian family; use the .rpm with dnf on RHEL family)
sudo apt install ./medaudit_0.25.0+m23-1_amd64.deb
#    Interactive installs prompt for this site's hospital ID and name;
#    the service then starts automatically.

# 2. (Optional) Set/change this site's hospital later, then restart
sudo vi /etc/medaudit/medaudit.env     # MEDAUDIT_SITE_HOSPITAL_ID / _NAME
sudo systemctl restart medaudit-server

# 3. Open http://<server>:8080 — initial account: admin
#    (password change is forced on first Web login).
#    On a category page, click "Start audit" on an object, then
#    "Export report".
```

## Audit targets and rules

| Category | Targets | Coverage |
| --- | --- | --- |
| Databases | Oracle, MySQL, SQL Server, PostgreSQL | accounts, roles, system/object privileges, password policy, remote access |
| Operating systems | Linux, Windows, HP-UX | accounts and privilege-escalation surface, services and startup items, critical file permissions |
| Middleware | Tomcat, Nginx, IIS, WebLogic | admin-surface exposure, runtime account, configuration baselines |
| APIs | HTTP APIs (OpenAPI-driven) | authentication and authorization checks (26 apicheck items) |

**65 built-in rules.** Conclusions distinguish PASS / FAIL / UNKNOWN /
NOT_RUN / NOT_APPLICABLE — insufficient evidence is honestly reported
as UNKNOWN, never folded into a pass. Beyond per-target rules, the
platform performs **correlation analysis**: cross-target permission
graphs, privilege-escalation path solving, effective-permission
computation, and cross-run drift comparison.

Business-required privileges can be exempted through **baselines**
(one-click "add to baseline" from a finding, with per-item derivation
and an audit trail). A check that does not apply site-wide can be
**disabled per rule by an engineer** with a mandatory reason; disabled
checks do not appear in reports.

## Supported platforms

**Server** (where medaudit-server runs):

| Family | Package | Notes |
| --- | --- | --- |
| Debian family (Debian, Ubuntu) | deb | systemd unit, enabled at boot |
| RHEL family (RHEL, Rocky, AlmaLinux, CentOS) | rpm | same |
| Other Linux | build from source | `go build`, bring your own unit |

Prebuilt packages are x86_64. All databases (including Oracle) use
pure-Go drivers — zero external dependencies, no client libraries to
install.

**Targets** need no agent: databases are queried over their native
protocols with read-only statements; Linux / HP-UX over SSH with a
fixed read-only command set; Windows over WinRM with a one-time pushed
collector; middleware over SSH or from a local directory; APIs over
read-only HTTP(S) probes.

## Installation

**Option 1 — Release packages (recommended):** download the `.deb` /
`.rpm` from the GitHub Release page and install. Installation creates
the `medaudit` system user, generates the evidence encryption key
(into `/etc/medaudit/medaudit.env` — back it up; losing it makes
historical evidence unreadable), interactively asks for this site's
hospital (skipped when there is no terminal), and registers and starts
the systemd service. Both packages have zero external dependencies
(static Go binaries; no runtime needs to be preinstalled).

**Option 2 — build from source:**

```
cd web && npm ci && npm run build && cd ..       # frontend (web/dist)
go build -o bin/ ./cmd/medaudit-server ./cmd/medaudit-collector ./cmd/ma
./package.sh 0.25.0-m23                          # assemble release tree (optional)
```

Layout after installation: programs in `/opt/medaudit`, configuration
in `/etc/medaudit/medaudit.env`, data in `/var/lib/medaudit` (SQLite
platform database and evidence), CLI available as `/usr/bin/ma*`
symlinks. See `docs/operations-guide.md` for the full deployment and
acceptance procedure (Chinese).

## Releases

Versions look like `0.25.0-m23`. Tagging `v<version>` and pushing marks
a release; the maintainer builds the deb/rpm (see `packaging/`) and
attaches them to the GitHub Release.

## Usage at a glance

**Customers use the Web UI for exactly two things**: click "Start
audit" on an object, and send the exported Word report to the system
owner; after remediation, audit again and use the recheck comparison
to confirm fixed / still present / newly appeared.

**Engineers use the `ma` command** (bare `ma` prints the function index):

```
ma login                                  # log in (session in ~/.medaudit/session.json)
ma use h-demo                             # switch current hospital context
ma assetls                                # list registered audit targets
ma audit db-mysql-01 -e MYSQL_PW          # audit one target (password via env, never stored)
ma find -c FAIL                           # list findings (filter by rule/target)
ma eval <bundle-id> -b bl-vendor          # re-evaluate with a baseline
ma report db-mysql-01 -o report.docx      # export a Word report
ma rules                                 # rules and site enable/disable state
ma srv                                    # server status
```

Full references: `docs/cli-guide.md` and `docs/operations-guide.md`
(Chinese).

## Configuration

Everything lives in `/etc/medaudit/medaudit.env`: platform database
path, collector paths, display timezone (`MEDAUDIT_DISPLAY_TZ`,
default Asia/Shanghai; times are stored in UTC and rendered in this
timezone), the site hospital (`MEDAUDIT_SITE_HOSPITAL_ID` / `_NAME`),
the evidence key, and the Oracle client library path. Restart
`medaudit-server` to apply changes.

## How it works

1. The collector connects to the target **read-only** (read-only
   database queries, a fixed read-only SSH command set, a one-time
   WinRM push, read-only API probes) and packs permission facts plus a
   collection receipt into a fact bundle; anything it could not collect
   is stated in the receipt, and execution status distinguishes
   COMPLETE / PARTIAL / FAILED.
2. The platform archives bundles (evidence encrypted with
   AES-256-GCM) and the rules engine evaluates facts; every conclusion
   traces back to fact IDs.
3. The correlation engine builds a permission graph over a bundle's
   facts, solves escalation paths and effective permissions; cross-run
   comparison yields drift and recheck verdicts.
4. Reports are generated from evaluation snapshots as Word documents —
   findings, risk, remediation guidance, and evidence summaries, with
   baseline exemptions and rule toggles honestly applied.

## Security notes

- Collection is strictly read-only: no writes to targets, no privilege
  changes, no business-table reads. Collector and platform identities
  are separate; use a dedicated low-privilege collection account per
  target.
- Audit passwords are **never stored**: in Web one-click audits the
  password only enters the collector subprocess environment; in the CLI
  it comes from an environment variable or an interactive prompt.
- The initial administrator password is a publicly documented product
  default and **changing it is forced at first Web login** — do so
  immediately after deployment.
- `/etc/medaudit/medaudit.env` contains the evidence key; it is mode
  0640 — include it in backups and guard it accordingly.
- Platform sessions are in-memory; a server restart requires logging
  in again (expected behavior).

## Limitations

- HP-UX collection is fully verified against command-transcript
  golden fixtures; verification on a real HP-UX host is pending site
  access (all other target types are verified end-to-end on real
  systems, see below).
- Oracle `tab_privs` collection has a 5000-row window on very large
  databases; bundles honestly report PARTIAL instead of silently
  truncating.
- WebLogic collection is directory-level (config.xml and related
  artifacts); it does not connect to a domain runtime.
- Windows remote audit requires the target to call back to the
  platform `server_url` for a one-time collection token.
- Offline evaluation (`ma offeval`) does not apply site rule toggles;
  the difference from online evaluation is documented in the manual.

## Test records

All verified in real environments (laboratory, October 2026):

| Target | Scenario | Result |
| --- | --- | --- |
| Oracle 19c | Full CDB collection, 8528 facts, evaluation | Done; baseline exemption arithmetic verified |
| MySQL 8.4 / 8.0 | Collection, evaluation, one-click baseline exemption | Done |
| SQL Server 2022 | Collection, 313 facts, evaluation | Done |
| PostgreSQL 16 | Collection, evaluation, baseline | Done |
| Windows Server 2019 (domain controller) | WinRM remote audit, 1169 facts | Done |
| Linux (Debian 12) | Local + SSH remote collection, service enumeration | Done |
| HP-UX | Transcript golden fixtures (8 planted findings hit exactly) | Pass (real host pending) |
| Tomcat 9 / Nginx | In-container local collection | Done |
| IIS / WebLogic | Remote audit / configuration-artifact audit | Done |
| API (apicheck) | 26 checks against golden expectations | Done (PASS 19 / FAIL 6 / NOT_RUN 1) |
| deb / rpm packages | Install, start/stop, erase on Debian 12 and a Rocky 9 container | Pass |

## License

MedAudit is published under the **Weixun Source License 1.0**
(source available; not an Open Source license): personal use and
non-production use (evaluation, testing, development, laboratory) are
free; production use by a for-profit organization requires a commercial
license obtained in advance. The Licensor is Xiamen
Weixun Information Technology Co., Ltd. Commercial licensing
inquiries: **sales@xmweixun.com**.

See [LICENSE](LICENSE), [LICENSING.md](LICENSING.md), and
[COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).
