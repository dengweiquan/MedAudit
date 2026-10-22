# MedAudit 试点准备包（M11 立项，M18 刷新）

面向首家医院试点落地的成套材料：部署、操作、实施清单与一套可直接加载的演示数据。
所有内容对应服务端版本 0.20.0-m18（规则 59 条）。M18 刷新纳入 M12 登录鉴权、M13 Oracle 规则补齐、M14/M16 工程师 CLI、M15 报告修复脚本、M17 单院部署与规则启停、M18 Word 新版式与口径修正；演示数据仍为 M11 实验室真实采集，未变更。

## 文件清单

| 文件 | 用途 |
|---|---|
| `deployment-guide.md` | 部署指南：系统要求、安装步骤、网络/账号矩阵、部署后检查、升级回退、排障 |
| `operator-manual.md` | 操作手册：从登记资产到出报告的完整现行流程与口径说明 |
| `pilot-checklist.md` | 试点实施清单：前置条件核对、试点验收标准、演示动线 |
| `smoke-test.sh` | 部署后自检（只读）：健康、版本、规则数、关键接口 |
| `load-demo.sh` | 演示数据一键加载：只调公开 API，任意新装实例可用 |
| `demo-data/` | 演示事实包与 API 报告（实验室真实采集，见下） |

## 演示数据说明（demo-data/）

演示医院 `h-demo`，全部为实验室环境真实采集的事实包（非编造、非真实医院数据）：

| 文件 | 内容 | 看点 |
|---|---|---|
| `demo-pg.zip` | PostgreSQL 16 | pg_hba trust/md5 等配置类 FAIL（实验室容器植入） |
| `demo-mysql-1.zip` / `demo-mysql-2.zip` | MySQL 8.0 同资产前后两包 | 两包之间植入：角色 demo_admin_role（SUPER）授予 demo_via、local_infile 打开 → 第二包命中「经角色派生 SUPER」且与第一包有漂移 |
| `demo-oracle-1.zip` / `demo-oracle-2.zip` | Oracle 19c CDB 双包 | 角色嵌套路径 PDB_DBA_TEST → DBA 等（关联分析素材）；执行 PARTIAL 是 5000 行上限的诚实口径 |
| `demo-linux.zip` | Linux 主机（实验室 kf7） | OS 事实全量；含用户 nurse1 与组 tomcatops（关联链素材） |
| `demo-tomcat.zip` | Tomcat（实验室夹具副本） | conf 目录组可写（tomcatops）+ 以 root 运行 → 与 OS 包组成跨层提权链 |
| `demo-api-report.json` | 业务接口越权报告（自研夹具） | 26 探针，6 条植入越权全命中 |

加载后工作台即有完整数据，动线见 `pilot-checklist.md` 第四节。

## 快速开始

```bash
# 1) 按 deployment-guide.md 安装并启动服务端
# 2) 自检
bash pilot/smoke-test.sh http://127.0.0.1:8080
# 3)（可选）加载演示数据
bash pilot/load-demo.sh http://127.0.0.1:8080
```
