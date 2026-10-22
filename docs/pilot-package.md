# M11 试点准备包（2026-10-21，生产 0.11.0-m11）

## 交付（pilot/，随安装包分发，package.sh 已集成）
- deployment-guide.md（系统要求/安装/网络矩阵/账号矩阵/备份回退/排障）
- operator-manual.md（现行操作手册：登记→三模式采集→评估基线→复核复测→关联/漂移→报告→边界）
- pilot-checklist.md（前置核对/执行步骤/验收标准/10 分钟演示动线）
- smoke-test.sh（只读自检；注：规则计数按 API 的 Go 大写键 ID 统计，首验时修正过一次口径）
- load-demo.sh + demo-data/（7 事实包 + API 报告，约 215KB，实验室真实采集）

## 演示数据生成要点（复现备忘）
- MySQL 漂移对：两采集间植入 demo_admin_role（SUPER）→demo_via 与 local_infile 开关；
  植入对象保留在 medaudit-test-mysql80 容器内（与 m8_* 同惯例）。
- Tomcat 跨层链：夹具副本 conf 改 tomcatops 组写；容器须以「与宿主机相同绝对路径」挂载并同设
  CATALINA_HOME/BASE（采集器按 catalina.home=<--home> 匹配进程命令行），否则无进程事实、链断在最后一跳。
  生成后容器与副本已删，事实已固化在 demo-tomcat.zip。
- 加载顺序：导入逐包间隔 2 秒——导入时间秒级、同秒落库会使「上一包」判定（漂移章节/UI 对比）失效；
  关联在报告之前生成，报告快照才带路径章节。

## 全新实例端到端验证（空库）
smoke 全绿 → load-demo 一次跑通：7 包导入、API 报告存档、全量评估、关联 8 条路径
（Oracle 角色嵌套 4 + MySQL 角色链 2 + 跨层 nurse1→tomcatops→conf→Tomcat→root 链 2）、5 份报告；
MySQL 报告漂移章节（新增 11/消失 1/重点 6）、Tomcat 报告路径章节、demo_via 有效权限 SUPER（派生）均核对属实。
生产校验：0.11.0-m11、规则 55、8 包不变、smoke 对生产全绿、安装包含 pilot/ 全量文件。

## M18 刷新（2026-10-21，生产 0.20.0-m18）

背景：M11 准备包停在 0.11.0 口径，与生产差 M12–M18 五组里程碑，用户点选刷新。

刷新内容（pilot/ 五件套，demo-data 未变更）：
- README：版本与规则数更新（0.20.0-m18 / 59 条），补刷新说明。
- deployment-guide：版本与包名更新；本地采集回传改「审计记录」页；部署后检查 59 条 + ctl 冒烟；备份节改写（平台在线备份 `GET /api/v1/admin/backup` 或 `masrvbak`（原 medauditctl server backup）首选，**WAL 警告：切勿直拷运行中的库主文件**，恢复=停服替换）；排障表加 ORA-01017 行（错误已带中文提示）。
- operator-manual：按现行产品全量重写——13 视图与客户/工程师分工、登记与删除在「管理」页、类别页「开始审计」闭环、问题页按规则分组、复检对比销账、报告自带修复/回滚脚本与新版 Word 章节、基线与规则启停分工（含大小写口径与离线 eval 不应用启停的边界）、工程师 CLI 命令地图（M23 起为 ma 命令族，原 medauditctl）、「最新一轮」间隙聚类口径、采集失败中文提示。
- pilot-checklist：新增本站医院初始化、默认口令修改、例外口径（基线/启停先与院方对齐）三组核对项；执行步骤改管理页登记与复检对比闭环；验收加新版式报告与启停留痕；演示动线页面名与入口全面更新（审计记录页工程师详情看漂移/有效权限），并注明演示加载的本站模式前提（未设本站或本站即 h-demo）。
- smoke-test.sh：规则数下限 59；接口检查新增 site、rule-toggles。
- load-demo.sh：仅更新结尾演示动线文案（逻辑未动；本站模式下登记演示医院与本站同名时脚本容忍已存在并继续，实证通过）。

重新打包：package.sh 0.20.0-m18 重跑，tar 覆盖更新（二进制与当日生产发布一致，仅 pilot/ 内容刷新）。

空库端到端实证（用新包内二进制+脚本，空库 + 本站模式 h-demo + 无证据密钥）：
- smoke-test.sh 全 PASS（14 项：健康/版本/Web/鉴权/登录/规则 59/八接口含 site 与 rule-toggles）；
- load-demo.sh 全程完成：7 包导入、逐包评估、关联 path_count=8、5 份报告生成；
- 金值核对：MySQL 漂移 added 11 / removed 1 / attention 6；有效权限 demo_via@% 经 demo_admin_role 派生（含 SUPER）；API 报告 FAIL 6；/api/v1/site 返回 h-demo；报告 docx 下载 200。
- 过程注记：外网侧经隧道抽查 drift/effective 时遇间歇空响应，kf7 本地直查稳定全过——为隧道抖动（与当日看门狗记录一致），非产品缺陷。
