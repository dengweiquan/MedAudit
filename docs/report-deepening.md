# M10 报告深化（2026-10-21，生产 0.10.0-m10）

## M10-1 API 审计报告 Word 导出
GET /api/v1/api-audits/{id}/docx（platform.RenderAPIAuditDocx，stdlib OOXML，与常规报告共用 packDocx）：
元信息表 → 结论汇总 → 越权命中（FAIL）清单 → 全量探针清单（上限 500 条，超出注明截断）。
ApiView 列表新增 Word 下载按钮，原「接口类报告无 Word」文案已修正。

## M10-2/M10-3 报告新章节（GenerateReport 快照并入，docx 与 Web 报告详情同步渲染）
- privilege_paths：取报告生成时点同医院最新一份「包含本事实包」的关联报告，摘录路径链/风险/
  图规模（清单上限 50 条，path_count 为全量）；无关联报告则整段缺省。
- drift：同资产同适配器上一事实包的 BundleDrift 摘要（新增/消失/重点关注计数为全量，清单各上限 100 条）；
  无上一包则整段缺省。
- 口径不变：报告快照不可变——旧报告不回填新章节，重新生成才有；两段均在快照内注明来源与口径。

## 验证（预发，生产库副本）
- API docx：存量夹具报告 apiaudit-20261020-052535（6 FAIL）下载，document.xml 结构与内容核对通过。
- 路径章节：对生产副本 Oracle 双包跑关联（4 条路径，含 PDB_DBA_TEST→DBA 直达链）→ 新报告快照
  含 privilege_paths，docx 章节与链文本正确。
- 漂移章节：MySQL80 后一包新报告含 drift（基线 050928 包；新增 18/消失 0/重点 6，与 M8 生产实测一致），
  且未入关联的包不带路径章节。
- 回归：无上一包/无关联的包生成报告两段皆缺省；旧报告 docx 重构（packDocx 抽取）后渲染正常。
- 生产校验：0.10.0-m10、规则 55、8 包不变、API docx 与旧报告 docx 均 200。
