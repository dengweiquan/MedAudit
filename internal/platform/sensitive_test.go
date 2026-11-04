package platform

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"medaudit/internal/facts"
	"medaudit/internal/rules"
)

// sensBundle 建模一次完整采集：各授权来源收据均为 ok（匹配逻辑测试用）。
// 不完整采集（缺失/被拒/截断）须用 sensBundleReceipts 显式构造。
func sensBundle(adapter facts.TargetType, fs ...facts.Fact) *facts.FactBundle {
	return sensBundleReceipts(adapter, []facts.Receipt{
		{TemplateID: "ora.tab_privs", Status: "ok"},
		{TemplateID: "ora.sys_privs", Status: "ok"},
		{TemplateID: "ora.cdb_sys_privs", Status: "ok"},
		{TemplateID: "pg.object_privileges", Status: "ok"},
		{TemplateID: "mysql.user_privs", Status: "ok"},
		{TemplateID: "mysql.global_grants", Status: "ok"},
		{TemplateID: "mysql.db_privs", Status: "ok"},
		{TemplateID: "mssql.db_permissions", Status: "ok"},
		{TemplateID: "ora.role_privs", Status: "ok"},
		{TemplateID: "ora.users", Status: "ok"},
		{TemplateID: "mysql.accounts", Status: "ok"},
	}, fs...)
}

func sensBundleReceipts(adapter facts.TargetType, rcs []facts.Receipt, fs ...facts.Fact) *facts.FactBundle {
	return &facts.FactBundle{
		Collector: facts.CollectorInfo{Adapter: adapter},
		Execution: facts.ExecutionComplete,
		Facts:     fs,
		Receipts:  rcs,
	}
}

func privFact(id, source, subject, scope string, attrs map[string]string) facts.Fact {
	return facts.Fact{FactID: id, Kind: facts.FactPrivilege, Subject: subject,
		Status: facts.StatusObserved, Source: source, Scope: scope, Attributes: attrs}
}

func roleEdgeFact(role, user string, activation facts.Activation) facts.Fact {
	return facts.Fact{Kind: facts.FactRoleEdge, Subject: user, Status: facts.StatusObserved,
		Source:         "ora.role_privs",
		PermissionPath: []string{role, user}, Activation: activation}
}

func containerFact(conName string) facts.Fact {
	return facts.Fact{FactID: "c0", Kind: facts.FactAccountConfig, Subject: "container",
		Status: facts.StatusObserved, Source: "ora.container",
		Attributes: map[string]string{"con_name": conName, "con_id": "3"}}
}

func accountFact(id, source, subject string) facts.Fact {
	return facts.Fact{FactID: id, Kind: facts.FactAccountConfig, Subject: subject,
		Status: facts.StatusObserved, Source: source}
}

func readReportSnapshot(t *testing.T, db *sql.DB, id string) map[string]any {
	t.Helper()
	var raw string
	if err := db.QueryRow(`SELECT snapshot FROM reports WHERE id = ?`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		t.Fatal(err)
	}
	return snap
}

func keysOf(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// snapCategory 取报告快照敏感节第一条标签的类别（无节时返回 ""）。
func snapCategory(t *testing.T, snap map[string]any) string {
	t.Helper()
	sec, ok := snap["sensitive"].(map[string]any)
	if !ok {
		return ""
	}
	labels, ok := sec["labels"].([]any)
	if !ok || len(labels) == 0 {
		return ""
	}
	l, ok := labels[0].(map[string]any)
	if !ok {
		return ""
	}
	cat, _ := l["category"].(string)
	return cat
}

func findSnap(t *testing.T, sec *SensitiveSection, id string) SensitiveLabelSnap {
	t.Helper()
	for _, s := range sec.Labels {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("未找到标签快照 %s", id)
	return SensitiveLabelSnap{}
}

func countExposures(sec *SensitiveSection, labelID string, exemptOnly bool) int {
	n := 0
	for _, e := range sec.Exposures {
		if e.LabelID == labelID && e.Exempt == exemptOnly {
			n++
		}
	}
	return n
}

func TestNormalizeIdentifier(t *testing.T) {
	if got := NormalizeIdentifier("db-oracle", "his_patients"); got != "HIS_PATIENTS" {
		t.Errorf("Oracle 未引用应转大写，得到 %s", got)
	}
	if got := NormalizeIdentifier("db-oracle", `"His_Patients"`); got != "His_Patients" {
		t.Errorf("Oracle 引用名应保留原大小写，得到 %s", got)
	}
	if got := NormalizeIdentifier("db-postgres", "Patients"); got != "patients" {
		t.Errorf("PG 未引用应转小写，得到 %s", got)
	}
	if got := NormalizeIdentifier("db-mysql", "Patients"); got != "Patients" {
		t.Errorf("MySQL 应原样保留，得到 %s", got)
	}
}

// Oracle：PUBLIC 精确匹配 + 同名不同模式不匹配 + 大小写规范化。
func TestSensitiveOraclePublic(t *testing.T) {
	b := sensBundle("db-oracle",
		privFact("f1", "ora.tab_privs", "PUBLIC", "HIS.PATIENTS", map[string]string{"privilege": "SELECT"}),
		privFact("f2", "ora.tab_privs", "PUBLIC", "LIS.PATIENTS", map[string]string{"privilege": "SELECT"}),
	)
	labels := []SensitiveLabel{
		{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"},
		{ID: "l2", Schema: "EMR", Table: "PATIENTS", Category: "患者身份"},
	}
	sec := MatchSensitive(b, labels, nil)
	if s := findSnap(t, sec, "l1"); s.Status != "exposed" {
		t.Errorf("HIS.PATIENTS 应 exposed，得到 %s", s.Status)
	}
	if n := countExposures(sec, "l1", false); n != 1 {
		t.Errorf("l1 应有 1 条违规暴露，得到 %d", n)
	}
	if s := findSnap(t, sec, "l2"); s.Status != "no-broad-grant" {
		t.Errorf("同名不同模式（EMR.PATIENTS）不应匹配，得到 %s", s.Status)
	}
	if sec.Exposures[0].Evidence[0] != "f1" {
		t.Errorf("暴露应引用原始事实 f1，得到 %v", sec.Exposures[0].Evidence)
	}
}

// Oracle ANY：SYS 排除、DBA 豁免、默认角色传递、非默认角色不计。
func TestSensitiveOracleANY(t *testing.T) {
	b := sensBundle("db-oracle",
		privFact("a1", "ora.sys_privs", "APP_READER", "instance", map[string]string{"privilege": "SELECT ANY TABLE"}),
		privFact("a2", "ora.sys_privs", "DBA", "instance", map[string]string{"privilege": "SELECT ANY TABLE"}),
		privFact("a3", "ora.sys_privs", "RPT_ROLE", "instance", map[string]string{"privilege": "DELETE ANY TABLE"}),
		privFact("a4", "ora.sys_privs", "TMP_ROLE", "instance", map[string]string{"privilege": "SELECT ANY TABLE"}),
		accountFact("u1", "ora.users", "APP_READER"),
		accountFact("u2", "ora.users", "BOB"),
		roleEdgeFact("RPT_ROLE", "BOB", facts.ActivationDefault),
		roleEdgeFact("TMP_ROLE", "CAROL", facts.ActivationConditional),
	)
	labels := []SensitiveLabel{
		{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"},
		{ID: "l2", Schema: "SYS", Table: "USER$", Category: "口令字典"},
	}
	sec := MatchSensitive(b, labels, nil)
	if s := findSnap(t, sec, "l1"); s.Status != "exposed" {
		t.Errorf("HIS 表应被 ANY 暴露，得到 %s", s.Status)
	}
	// l1 暴露：APP_READER 直接 + BOB 经默认角色；DBA 跳过；CAROL 非默认不计。
	if n := countExposures(sec, "l1", false); n != 2 {
		t.Errorf("l1 应有 2 条暴露（直接+默认角色），得到 %d", n)
	}
	for _, e := range sec.Exposures {
		if e.Subject == "DBA" || e.Subject == "CAROL" {
			t.Errorf("DBA/CAROL 不应出现在暴露中：%+v", e)
		}
	}
	if s := findSnap(t, sec, "l2"); s.Status != "no-broad-grant" {
		t.Errorf("SYS 模式不在 ANY 可达范围，得到 %s", s.Status)
	}
}

// PG：PUBLIC 精确匹配（库/模式/对象三元组）。
func TestSensitivePGPublic(t *testing.T) {
	b := sensBundle("db-postgres",
		privFact("p1", "pg.object_privileges", "PUBLIC", "database:hisdb/schema:public",
			map[string]string{"privilege": "SELECT", "object": "patients", "schema": "public", "database": "hisdb"}),
	)
	labels := []SensitiveLabel{
		{ID: "l1", Database: "hisdb", Schema: "public", Table: "patients", Category: "患者身份"},
		{ID: "l2", Database: "hisdb", Schema: "private", Table: "patients", Category: "患者身份"},
		{ID: "l3", Database: "otherdb", Schema: "public", Table: "patients", Category: "患者身份"},
	}
	sec := MatchSensitive(b, labels, nil)
	if s := findSnap(t, sec, "l1"); s.Status != "exposed" {
		t.Errorf("l1 应 exposed，得到 %s", s.Status)
	}
	for _, id := range []string{"l2", "l3"} {
		if s := findSnap(t, sec, id); s.Status != "no-broad-grant" {
			t.Errorf("%s 不应匹配（模式/库不同），得到 %s", id, s.Status)
		}
	}
}

// MySQL：全局可达全部库表；库级只达本库；动态权限不算数据暴露。
func TestSensitiveMySQLScopes(t *testing.T) {
	b := sensBundle("db-mysql",
		privFact("m1", "mysql.user_privs", "app@%", "*.*", map[string]string{"privilege": "SELECT"}),
		privFact("m2", "mysql.db_privs", "lis@%", "lisdb.*", map[string]string{"privilege": "SELECT"}),
		privFact("m3", "mysql.global_grants", "ops@%", "*.*", map[string]string{"privilege": "CONNECTION_ADMIN", "dynamic": "true"}),
		accountFact("u1", "mysql.accounts", "app@%"),
		accountFact("u2", "mysql.accounts", "lis@%"),
	)
	labels := []SensitiveLabel{
		{ID: "l1", Database: "hisdb", Schema: "", Table: "patients", Category: "患者身份"},
		{ID: "l2", Database: "lisdb", Schema: "", Table: "results", Category: "检验"},
	}
	sec := MatchSensitive(b, labels, nil)
	if s := findSnap(t, sec, "l1"); s.Status != "exposed" {
		t.Errorf("全局 SELECT 应暴露全部库表，l1 得到 %s", s.Status)
	}
	if n := countExposures(sec, "l1", false); n != 1 {
		t.Errorf("l1 应有 1 条暴露（全局），得到 %d（动态权限不应计入）", n)
	}
	if n := countExposures(sec, "l2", false); n != 2 {
		t.Errorf("l2 应有 2 条暴露（全局+库级），得到 %d", n)
	}
}

// MSSQL：public 授权对象未采集——列为未确认，不计暴露、不判安全。
func TestSensitiveMSSQLUnconfirmed(t *testing.T) {
	b := sensBundle("db-sqlserver",
		privFact("s1", "mssql.db_permissions", "public", "database:hisdb",
			map[string]string{"permission": "SELECT", "state": "GRANT", "class": "DATABASE"}),
	)
	sec := MatchSensitive(b, []SensitiveLabel{{ID: "l1", Database: "hisdb", Schema: "dbo", Table: "patients", Category: "患者身份"}}, nil)
	if s := findSnap(t, sec, "l1"); s.Status != "unconfirmed" {
		t.Errorf("MSSQL public 应为 unconfirmed，得到 %s", s.Status)
	}
	if n := countExposures(sec, "l1", false); n != 0 {
		t.Errorf("MSSQL 未确认不应计暴露，得到 %d", n)
	}
}

// 基线合法豁免：放行项覆盖的暴露标 exempt，不计违规。
func TestSensitiveBaselineExempt(t *testing.T) {
	b := sensBundle("db-oracle",
		privFact("f1", "ora.tab_privs", "PUBLIC", "HIS.PATIENTS", map[string]string{"privilege": "SELECT"}),
	)
	bl := &rules.Baseline{Allows: []rules.BaselineAllow{
		{Subject: "PUBLIC", Kind: "privilege", Value: "SELECT", Scope: "HIS.PATIENTS"},
	}}
	sec := MatchSensitive(b, []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}, bl)
	if s := findSnap(t, sec, "l1"); s.Status != "no-broad-grant" {
		t.Errorf("全部放行时标签应为 no-broad-grant，得到 %s", s.Status)
	}
	if n := countExposures(sec, "l1", true); n != 1 {
		t.Errorf("应有 1 条豁免暴露，得到 %d", n)
	}
	if n := countExposures(sec, "l1", false); n != 0 {
		t.Errorf("豁免暴露不应计违规，得到 %d", n)
	}
}

// 列级标记：表级 broad 授权仍计暴露（附列级未覆盖注记）；无授权时不判安全。
func TestSensitiveColumnLabel(t *testing.T) {
	b := sensBundle("db-oracle",
		privFact("f1", "ora.tab_privs", "PUBLIC", "HIS.PATIENTS", map[string]string{"privilege": "SELECT"}),
	)
	sec := MatchSensitive(b, []SensitiveLabel{
		{ID: "l1", Schema: "HIS", Table: "PATIENTS", Column: "ID_NO", Category: "患者身份"},
	}, nil)
	s := findSnap(t, sec, "l1")
	if s.Status != "exposed" {
		t.Errorf("表级 PUBLIC 应暴露列级标记，得到 %s", s.Status)
	}
	found := false
	for _, n := range s.Notes {
		if strings.Contains(n, "列级") {
			found = true
		}
	}
	if !found {
		t.Errorf("列级标记应附列级未覆盖注记，得到 %v", s.Notes)
	}
	// 无授权事实且无收据（采集不完整）：不得称“未发现”，应为未确认。
	empty := sensBundleReceipts("db-oracle", nil)
	sec2 := MatchSensitive(empty, []SensitiveLabel{
		{ID: "l1", Schema: "HIS", Table: "PATIENTS", Column: "ID_NO", Category: "患者身份"},
	}, nil)
	s2 := findSnap(t, sec2, "l1")
	if s2.Status != "unconfirmed" {
		t.Errorf("无授权事实且无收据时列级标记应为 unconfirmed，得到 %s", s2.Status)
	}
	joined := strings.Join(sec2.Notes, " ")
	if !strings.Contains(joined, "缺授权事实不等于安全") {
		t.Errorf("无授权事实时应注记缺事实不等于安全，得到 %v", sec2.Notes)
	}
}

// 标记 CRUD：幂等、改类别升版本、删。
func TestSensitiveLabelCRUD(t *testing.T) {
	db := openTestDB(t, "sens.db")
	if err := CreateHospital(db, "h1", "医院一"); err != nil {
		t.Fatal(err)
	}
	if err := CreateAsset(db, Asset{ID: "a1", HospitalID: "h1", Kind: "db-oracle", Name: "Ora"}); err != nil {
		t.Fatal(err)
	}
	l1, err := UpsertSensitiveLabel(db, "db-oracle", "tester", SensitiveLabel{
		Hospital: "h1", Asset: "a1", Schema: "his_patients", Table: "patients", Category: "患者身份"})
	if err != nil {
		t.Fatal(err)
	}
	if l1.Schema != "HIS_PATIENTS" || l1.Table != "PATIENTS" || l1.Version != 1 {
		t.Errorf("写入时 Oracle 名应规范化大写且 version=1，得到 %+v", l1)
	}
	// 重复请求：同自然键同类别 → 同 ID、不升版本、不重复行。
	l2, err := UpsertSensitiveLabel(db, "db-oracle", "tester", SensitiveLabel{
		Hospital: "h1", Asset: "a1", Schema: "HIS_PATIENTS", Table: "PATIENTS", Category: "患者身份"})
	if err != nil {
		t.Fatal(err)
	}
	if l2.ID != l1.ID || l2.Version != 1 {
		t.Errorf("重复请求应幂等（同 ID、version 1），得到 %+v", l2)
	}
	// 改类别 → version +1。
	l3, err := UpsertSensitiveLabel(db, "db-oracle", "tester", SensitiveLabel{
		Hospital: "h1", Asset: "a1", Schema: "HIS_PATIENTS", Table: "PATIENTS", Category: "诊疗"})
	if err != nil {
		t.Fatal(err)
	}
	if l3.ID != l1.ID || l3.Version != 2 || l3.Category != "诊疗" {
		t.Errorf("改类别应同 ID、version 2，得到 %+v", l3)
	}
	rows, err := ListSensitiveLabels(db, "h1", "a1")
	if err != nil || len(rows) != 1 {
		t.Fatalf("应恰好 1 行，得到 %d（err=%v）", len(rows), err)
	}
	// 改删：PUT 改类别、DELETE 删。
	upd, err := UpdateSensitiveLabelCategory(db, l1.ID, "费用")
	if err != nil || upd.Version != 3 {
		t.Fatalf("PUT 改类别应 version 3，得到 %+v（err=%v）", upd, err)
	}
	ok, err := DeleteSensitiveLabel(db, l1.ID)
	if err != nil || !ok {
		t.Fatalf("删除应命中，ok=%v err=%v", ok, err)
	}
	rows, _ = ListSensitiveLabels(db, "h1", "a1")
	if len(rows) != 0 {
		t.Errorf("删除后应为空，得到 %d", len(rows))
	}
}

// 跨资产隔离：资产 B 的标签不进入资产 A 的报告节。
func TestSensitiveCrossAsset(t *testing.T) {
	db := openTestDB(t, "sens-cross.db")
	if err := CreateHospital(db, "h1", "医院一"); err != nil {
		t.Fatal(err)
	}
	if err := CreateAsset(db, Asset{ID: "a1", HospitalID: "h1", Kind: "db-oracle", Name: "Ora1"}); err != nil {
		t.Fatal(err)
	}
	if err := CreateAsset(db, Asset{ID: "a2", HospitalID: "h1", Kind: "db-oracle", Name: "Ora2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := UpsertSensitiveLabel(db, "db-oracle", "t", SensitiveLabel{
		Hospital: "h1", Asset: "a1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}); err != nil {
		t.Fatal(err)
	}
	if _, err := UpsertSensitiveLabel(db, "db-oracle", "t", SensitiveLabel{
		Hospital: "h1", Asset: "a2", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}); err != nil {
		t.Fatal(err)
	}
	b := sensBundle("db-oracle",
		privFact("f1", "ora.tab_privs", "PUBLIC", "HIS.PATIENTS", map[string]string{"privilege": "SELECT"}))
	sec := BuildSensitiveSection(db, "h1", "a1", b)
	if sec == nil || len(sec.Labels) != 1 {
		t.Fatalf("资产 A 的节应恰好含 A 的标签，得到 %+v", sec)
	}
	if sec.Labels[0].Status != "exposed" {
		t.Errorf("资产 A 的标签应 exposed，得到 %s", sec.Labels[0].Status)
	}
	secB := BuildSensitiveSection(db, "h1", "a2", b)
	if secB == nil || len(secB.Labels) != 1 || secB.Labels[0].Status != "exposed" {
		t.Fatalf("资产 B 同名标签在 B 的包上也应 exposed（同包事实），得到 %+v", secB)
	}
}

// 报告级：标签变化后新报告用新快照，旧报告快照不变义。
func TestSensitiveReportSnapshotImmutable(t *testing.T) {
	db := openTestDB(t, "sens-rep.db")
	seedBundle(t, db)
	// seedBundle 的包 JSON 无 collector：补上适配器，否则敏感节不建。
	if _, err := db.Exec(`UPDATE fact_bundles SET bundle = ?
		WHERE id = 'bundle-1'`, `{"collector":{"adapter":"db-mysql"},"facts":[],"receipts":[]}`); err != nil {
		t.Fatal(err)
	}
	// seedBundle 的包是 db-mysql 空事实；先上一条 MySQL 标签，再生成两份报告。
	if _, err := UpsertSensitiveLabel(db, "db-mysql", "t", SensitiveLabel{
		Hospital: "h-test", Asset: "a-mysql", Database: "hisdb", Schema: "", Table: "patients", Category: "患者身份"}); err != nil {
		t.Fatal(err)
	}
	rep1, err := GenerateReport(db, "h-test", "p1", "bundle-1", "tester")
	if err != nil {
		t.Fatal(err)
	}
	snap1 := readReportSnapshot(t, db, rep1)
	if snap1["sensitive"] == nil {
		t.Fatalf("首份报告应含敏感节，得到 keys：%v", keysOf(snap1))
	}
	// 改类别后生成第二份报告。
	if _, err := UpsertSensitiveLabel(db, "db-mysql", "t", SensitiveLabel{
		Hospital: "h-test", Asset: "a-mysql", Database: "hisdb", Schema: "", Table: "patients", Category: "诊疗"}); err != nil {
		t.Fatal(err)
	}
	rep2, err := GenerateReport(db, "h-test", "p1", "bundle-1", "tester")
	if err != nil {
		t.Fatal(err)
	}
	snap2 := readReportSnapshot(t, db, rep2)
	cat1 := snapCategory(t, snap1)
	cat2 := snapCategory(t, snap2)
	if cat1 != "患者身份" || cat2 != "诊疗" {
		t.Errorf("旧报告应为患者身份、新报告应为诊疗，得到 %q / %q", cat1, cat2)
	}
	// 旧报告重读仍为旧快照。
	snap1b := readReportSnapshot(t, db, rep1)
	if snapCategory(t, snap1b) != "患者身份" {
		t.Errorf("旧报告重读应仍为患者身份，得到 %q", snapCategory(t, snap1b))
	}
}

// 静态复核回归：相关来源不完整时不得称“未发现”。

// Oracle：tab_privs 收据截断/被拒/缺失 → 未确认（即使无命中）；收据齐全无命中 → 未发现。
func TestSensitiveReceiptIncomplete(t *testing.T) {
	lbl := []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	mk := func(rcs []facts.Receipt) *facts.FactBundle {
		return sensBundleReceipts("db-oracle", rcs)
	}
	ok := []facts.Receipt{
		{TemplateID: "ora.tab_privs", Status: "ok"},
		{TemplateID: "ora.sys_privs", Status: "ok"},
	}
	for _, tc := range []struct {
		name string
		rcs  []facts.Receipt
		want string
	}{
		{"截断", []facts.Receipt{{TemplateID: "ora.tab_privs", Status: "partial"}, {TemplateID: "ora.sys_privs", Status: "ok"}}, "unconfirmed"},
		{"被拒", []facts.Receipt{{TemplateID: "ora.tab_privs", Status: "denied"}, {TemplateID: "ora.sys_privs", Status: "ok"}}, "unconfirmed"},
		{"缺失", []facts.Receipt{{TemplateID: "ora.sys_privs", Status: "ok"}}, "unconfirmed"},
		{"齐全", ok, "no-broad-grant"},
	} {
		s := findSnap(t, MatchSensitive(mk(tc.rcs), lbl, nil), "l1")
		if s.Status != tc.want {
			t.Errorf("%s: want %s, got %s", tc.name, tc.want, s.Status)
		}
	}
}

// 已有可靠暴露证据时，即使其他来源不完整仍报告风险（不被未确认掩盖）。
func TestSensitiveExposedDespiteIncomplete(t *testing.T) {
	b := sensBundleReceipts("db-oracle",
		[]facts.Receipt{{TemplateID: "ora.tab_privs", Status: "partial"}, {TemplateID: "ora.sys_privs", Status: "ok"}},
		privFact("f1", "ora.tab_privs", "PUBLIC", "HIS.PATIENTS", map[string]string{"privilege": "SELECT"}),
	)
	s := findSnap(t, MatchSensitive(b, []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}, nil), "l1")
	if s.Status != "exposed" {
		t.Errorf("已有 PUBLIC 暴露时应为 exposed，得到 %s", s.Status)
	}
}

// MSSQL：即使无数据库级 public 授权，对象级事实未采集 → 恒为未确认，不得称“未发现”。
func TestSensitiveMSSQLNoPublicUnconfirmed(t *testing.T) {
	b := sensBundle("db-sqlserver")
	s := findSnap(t, MatchSensitive(b, []SensitiveLabel{{ID: "l1", Database: "hisdb", Schema: "dbo", Table: "patients", Category: "患者身份"}}, nil), "l1")
	if s.Status != "unconfirmed" {
		t.Errorf("MSSQL 无 public 时应为 unconfirmed，得到 %s", s.Status)
	}
}

// Oracle 容器归属：标签库名须与包容器对应，否则未确认（同名表在不同 PDB 是不同对象）。
// 静态复核回归三轮：容器身份只认可信的 ora.container 事实 + 收据，
// Scope.Container（旧包中的服务名）不再作为依据。
func TestSensitiveOracleContainer(t *testing.T) {
	fact := privFact("f1", "ora.tab_privs", "PUBLIC", "HIS.PATIENTS", map[string]string{"privilege": "SELECT"})
	lbl := func(db string) []SensitiveLabel {
		return []SensitiveLabel{{ID: "l1", Database: db, Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	}
	// 新包：Scope 是服务名、事实是 PDB 名，事实胜出 → 暴露。
	// 标签库名小写未引用输入，匹配时规范化为大写，与字典大写容器名精确匹配。
	b := sensBundleReceipts("db-oracle",
		[]facts.Receipt{{TemplateID: "ora.tab_privs", Status: "ok"}, {TemplateID: "ora.sys_privs", Status: "ok"}, {TemplateID: "ora.container", Status: "ok"}},
		fact, containerFact("PDB1"))
	b.Scope.Container = "orclservice"
	if s := findSnap(t, MatchSensitive(b, lbl("pdb1"), nil), "l1"); s.Status != "exposed" {
		t.Errorf("service≠PDB 但事实一致：want exposed, got %s", s.Status)
	}
	// 引用标签库名：去引号保留原样，与引用 PDB 名精确匹配；与大写 PDB 名不匹配。
	b = sensBundleReceipts("db-oracle",
		[]facts.Receipt{{TemplateID: "ora.tab_privs", Status: "ok"}, {TemplateID: "ora.sys_privs", Status: "ok"}, {TemplateID: "ora.container", Status: "ok"}},
		fact, containerFact("Pdb1"))
	if s := findSnap(t, MatchSensitive(b, lbl(`"Pdb1"`), nil), "l1"); s.Status != "exposed" {
		t.Errorf("引用库名一致：want exposed, got %s", s.Status)
	}
	b = sensBundleReceipts("db-oracle",
		[]facts.Receipt{{TemplateID: "ora.tab_privs", Status: "ok"}, {TemplateID: "ora.sys_privs", Status: "ok"}, {TemplateID: "ora.container", Status: "ok"}},
		fact, containerFact("PDB1"))
	if s := findSnap(t, MatchSensitive(b, lbl(`"Pdb1"`), nil), "l1"); s.Status != "unconfirmed" {
		t.Errorf("引用库名与大写容器名不匹配：want unconfirmed, got %s", s.Status)
	}
	// 旧包：Scope 非空且恰好等于标签库名，但无容器事实 → 未确认（服务名不作数）。
	b = sensBundle("db-oracle", fact)
	b.Scope.Container = "pdb1"
	if s := findSnap(t, MatchSensitive(b, lbl("pdb1"), nil), "l1"); s.Status != "unconfirmed" {
		t.Errorf("旧包非空 Scope：want unconfirmed, got %s", s.Status)
	}
	// 容器收据失败：事实存在也不可信 → 未确认。
	b = sensBundleReceipts("db-oracle",
		[]facts.Receipt{{TemplateID: "ora.tab_privs", Status: "ok"}, {TemplateID: "ora.sys_privs", Status: "ok"}, {TemplateID: "ora.container", Status: "failed"}},
		fact, containerFact("PDB1"))
	if s := findSnap(t, MatchSensitive(b, lbl("pdb1"), nil), "l1"); s.Status != "unconfirmed" {
		t.Errorf("容器收据失败：want unconfirmed, got %s", s.Status)
	}
	// 容器事实与标签不符 → 未确认。
	b = sensBundleReceipts("db-oracle",
		[]facts.Receipt{{TemplateID: "ora.tab_privs", Status: "ok"}, {TemplateID: "ora.sys_privs", Status: "ok"}, {TemplateID: "ora.container", Status: "ok"}},
		fact, containerFact("PDB2"))
	if s := findSnap(t, MatchSensitive(b, lbl("pdb1"), nil), "l1"); s.Status != "unconfirmed" {
		t.Errorf("容器事实不符：want unconfirmed, got %s", s.Status)
	}
	// 标签无库名：无需容器身份 → 暴露（Scope 仍可为服务名）。
	b = sensBundle("db-oracle", fact)
	b.Scope.Container = "orclservice"
	if s := findSnap(t, MatchSensitive(b, lbl(""), nil), "l1"); s.Status != "exposed" {
		t.Errorf("标签无库名：want exposed, got %s", s.Status)
	}
}

// MySQL 库名大小写：按 lower_case_table_names 匹配，未知时保守按区分处理。
func TestSensitiveMySQLCase(t *testing.T) {
	priv := privFact("f1", "mysql.db_privs", "app", "HisDB.*", map[string]string{"privilege": "SELECT"})
	lbl := []SensitiveLabel{{ID: "l1", Database: "hisdb", Schema: "", Table: "patients", Category: "患者身份"}}
	mk := func(lct string) *facts.FactBundle {
		fs := []facts.Fact{priv, accountFact("u1", "mysql.accounts", "app")}
		if lct != "" {
			fs = append(fs, facts.Fact{FactID: "c1", Kind: facts.FactAccountConfig, Subject: "global",
				Status: facts.StatusObserved, Source: "mysql.server_config",
				Attributes: map[string]string{"name": "lower_case_table_names", "value": lct}})
			// 已知模式的用例须给配置事实配可信收据，否则模式仍未知。
			return sensBundleReceipts("db-mysql",
				[]facts.Receipt{
					{TemplateID: "mysql.user_privs", Status: "ok"},
					{TemplateID: "mysql.global_grants", Status: "ok"},
					{TemplateID: "mysql.db_privs", Status: "ok"},
					{TemplateID: "mysql.server_config", Status: "ok"},
					{TemplateID: "mysql.accounts", Status: "ok"},
				}, fs...)
		}
		return sensBundle("db-mysql", fs...)
	}
	for _, tc := range []struct {
		name string
		lct  string
		want string
	}{
		{"0区分", "0", "no-broad-grant"},
		{"1不区分", "1", "exposed"},
		{"未知仅大小写不同 → 未确认", "", "unconfirmed"},
	} {
		s := findSnap(t, MatchSensitive(mk(tc.lct), lbl, nil), "l1")
		if s.Status != tc.want {
			t.Errorf("%s: want %s, got %s", tc.name, tc.want, s.Status)
		}
	}
}

// 静态复核回归二轮：命中先验收据——来源被拒/失败/缺收据的事实不作确定暴露。
func TestSensitiveHitRequiresCredibleReceipt(t *testing.T) {
	hit := privFact("f1", "ora.tab_privs", "PUBLIC", "HIS.PATIENTS", map[string]string{"privilege": "SELECT"})
	lbl := []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	sysOK := facts.Receipt{TemplateID: "ora.sys_privs", Status: "ok"}
	for _, tc := range []struct {
		name string
		rcs  []facts.Receipt
		want string
	}{
		{"来源被拒", []facts.Receipt{{TemplateID: "ora.tab_privs", Status: "denied"}, sysOK}, "unconfirmed"},
		{"来源缺收据", []facts.Receipt{sysOK}, "unconfirmed"},
		{"来源失败", []facts.Receipt{{TemplateID: "ora.tab_privs", Status: "failed"}, sysOK}, "unconfirmed"},
		{"来源 partial 加命中可报告", []facts.Receipt{{TemplateID: "ora.tab_privs", Status: "partial"}, sysOK}, "exposed"},
		{"来源 ok", []facts.Receipt{{TemplateID: "ora.tab_privs", Status: "ok"}, sysOK}, "exposed"},
	} {
		s := findSnap(t, MatchSensitive(sensBundleReceipts("db-oracle", tc.rcs, hit), lbl, nil), "l1")
		if s.Status != tc.want {
			t.Errorf("%s: want %s, got %s", tc.name, tc.want, s.Status)
		}
	}
}

// 静态复核回归二轮：MySQL 模式未知时，仅大小写不同的库名不得判“未发现”；
// 配置事实无可信收据时模式仍未知；模式 2 与 1 同为不区分。
func TestSensitiveMySQLCaseUnknownIndeterminate(t *testing.T) {
	lbl := []SensitiveLabel{{ID: "l1", Database: "hisdb", Schema: "", Table: "patients", Category: "患者身份"}}
	coreOK := []facts.Receipt{
		{TemplateID: "mysql.user_privs", Status: "ok"},
		{TemplateID: "mysql.global_grants", Status: "ok"},
		{TemplateID: "mysql.db_privs", Status: "ok"},
		{TemplateID: "mysql.accounts", Status: "ok"},
	}
	acct := accountFact("u1", "mysql.accounts", "app")
	priv := func(db string) facts.Fact {
		return privFact("f1", "mysql.db_privs", "app", db+".*", map[string]string{"privilege": "SELECT"})
	}
	// 未知模式 + 仅大小写不同 → 未确认（不得称“未发现”）。
	s := findSnap(t, MatchSensitive(sensBundle("db-mysql", priv("HisDB"), acct), lbl, nil), "l1")
	if s.Status != "unconfirmed" {
		t.Errorf("未知模式 + 仅大小写不同：want unconfirmed, got %s", s.Status)
	}
	// 未知模式 + 精确相等 → 仍可匹配为暴露。
	s = findSnap(t, MatchSensitive(sensBundle("db-mysql", priv("hisdb"), acct), lbl, nil), "l1")
	if s.Status != "exposed" {
		t.Errorf("未知模式 + 精确相等：want exposed, got %s", s.Status)
	}
	// 未知模式 + 完全不同库名 → 无命中，可称“未发现”（来源齐全）。
	s = findSnap(t, MatchSensitive(sensBundle("db-mysql", priv("otherdb"), acct), lbl, nil), "l1")
	if s.Status != "no-broad-grant" {
		t.Errorf("未知模式 + 不同库名：want no-broad-grant, got %s", s.Status)
	}
	// 配置事实存在但 server_config 收据被拒 → 模式仍未知，仅大小写不同 → 未确认。
	lct := facts.Fact{FactID: "c1", Kind: facts.FactAccountConfig, Subject: "global",
		Status: facts.StatusObserved, Source: "mysql.server_config",
		Attributes: map[string]string{"name": "lower_case_table_names", "value": "1"}}
	rcs := append(append([]facts.Receipt{}, coreOK...),
		facts.Receipt{TemplateID: "mysql.server_config", Status: "denied"})
	s = findSnap(t, MatchSensitive(sensBundleReceipts("db-mysql", rcs, priv("HisDB"), lct, acct), lbl, nil), "l1")
	if s.Status != "unconfirmed" {
		t.Errorf("配置事实无可信收据 + 仅大小写不同：want unconfirmed, got %s", s.Status)
	}
	// 模式 2 与 1 同为不区分。
	lct2 := facts.Fact{FactID: "c1", Kind: facts.FactAccountConfig, Subject: "global",
		Status: facts.StatusObserved, Source: "mysql.server_config",
		Attributes: map[string]string{"name": "lower_case_table_names", "value": "2"}}
	rcs2 := append(append([]facts.Receipt{}, coreOK...),
		facts.Receipt{TemplateID: "mysql.server_config", Status: "ok"})
	s = findSnap(t, MatchSensitive(sensBundleReceipts("db-mysql", rcs2, priv("HisDB"), lct2, acct), lbl, nil), "l1")
	if s.Status != "exposed" {
		t.Errorf("模式 2 + 仅大小写不同：want exposed, got %s", s.Status)
	}
}

// 静态复核回归三轮：同来源冲突收据（ok 与 denied/failed 并存）不采信命中，
// 与收据排列顺序无关；ok+partial 仍可信。
func TestSensitiveConflictingReceipts(t *testing.T) {
	hit := privFact("f1", "ora.tab_privs", "PUBLIC", "HIS.PATIENTS", map[string]string{"privilege": "SELECT"})
	lbl := []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	sysOK := facts.Receipt{TemplateID: "ora.sys_privs", Status: "ok"}
	for _, tc := range []struct {
		name string
		rcs  []facts.Receipt
		want string
	}{
		{"ok 后 denied", []facts.Receipt{{TemplateID: "ora.tab_privs", Status: "ok"}, {TemplateID: "ora.tab_privs", Status: "denied"}, sysOK}, "unconfirmed"},
		{"denied 后 ok", []facts.Receipt{{TemplateID: "ora.tab_privs", Status: "denied"}, {TemplateID: "ora.tab_privs", Status: "ok"}, sysOK}, "unconfirmed"},
		{"ok 后 failed", []facts.Receipt{{TemplateID: "ora.tab_privs", Status: "ok"}, {TemplateID: "ora.tab_privs", Status: "failed"}, sysOK}, "unconfirmed"},
		{"ok 加 partial 仍可信", []facts.Receipt{{TemplateID: "ora.tab_privs", Status: "ok"}, {TemplateID: "ora.tab_privs", Status: "partial"}, sysOK}, "exposed"},
	} {
		s := findSnap(t, MatchSensitive(sensBundleReceipts("db-oracle", tc.rcs, hit), lbl, nil), "l1")
		if s.Status != tc.want {
			t.Errorf("%s: want %s, got %s", tc.name, tc.want, s.Status)
		}
	}
}

// 静态复核回归三轮：角色边逐条验收据——边来源不可信时角色授权可显示，
// 但实际用户可达性不计确定暴露（标签未确认）；边可信时正常暴露。
func TestSensitiveRoleEdgeUncredible(t *testing.T) {
	grant := privFact("a1", "ora.sys_privs", "RPT_ROLE", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	edge := roleEdgeFact("RPT_ROLE", "BOB", facts.ActivationDefault)
	lbl := []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	sysOK := facts.Receipt{TemplateID: "ora.sys_privs", Status: "ok"}
	tabOK := facts.Receipt{TemplateID: "ora.tab_privs", Status: "ok"}
	// 边收据被拒 → 未确认，且注记提及角色名与可达性。
	b := sensBundleReceipts("db-oracle",
		[]facts.Receipt{tabOK, sysOK, {TemplateID: "ora.role_privs", Status: "denied"}}, grant, edge)
	s := findSnap(t, MatchSensitive(b, lbl, nil), "l1")
	if s.Status != "unconfirmed" {
		t.Errorf("边收据被拒：want unconfirmed, got %s", s.Status)
	}
	found := false
	for _, n := range s.Notes {
		if strings.Contains(n, "RPT_ROLE") && strings.Contains(n, "可达性") {
			found = true
		}
	}
	if !found {
		t.Errorf("边不可信时注记应提及角色与可达性，得到 %v", s.Notes)
	}
	if n := countExposures(MatchSensitive(b, lbl, nil), "l1", false); n != 0 {
		t.Errorf("边不可信时不应有确定暴露，得到 %d", n)
	}
	// 边无收据 → 未确认。
	b = sensBundleReceipts("db-oracle", []facts.Receipt{tabOK, sysOK}, grant, edge)
	if s := findSnap(t, MatchSensitive(b, lbl, nil), "l1"); s.Status != "unconfirmed" {
		t.Errorf("边缺收据：want unconfirmed, got %s", s.Status)
	}
	// 边可信 + 成员为确认用户 → 暴露（经角色）。
	b = sensBundleReceipts("db-oracle",
		[]facts.Receipt{tabOK, sysOK, {TemplateID: "ora.role_privs", Status: "ok"}, {TemplateID: "ora.users", Status: "ok"}},
		grant, edge, accountFact("u1", "ora.users", "BOB"))
	if s := findSnap(t, MatchSensitive(b, lbl, nil), "l1"); s.Status != "exposed" {
		t.Errorf("边可信：want exposed, got %s", s.Status)
	}
}

// 静态复核回归三轮：MySQL 模式事实须为已观察的配置事实；Kind 或 Status
// 不符时模式仍未知，仅大小写不同的授权判未确认。
func TestSensitiveMySQLCaseFactValidation(t *testing.T) {
	priv := privFact("f1", "mysql.db_privs", "app", "HisDB.*", map[string]string{"privilege": "SELECT"})
	lbl := []SensitiveLabel{{ID: "l1", Database: "hisdb", Schema: "", Table: "patients", Category: "患者身份"}}
	coreOK := []facts.Receipt{
		{TemplateID: "mysql.user_privs", Status: "ok"},
		{TemplateID: "mysql.global_grants", Status: "ok"},
		{TemplateID: "mysql.db_privs", Status: "ok"},
		{TemplateID: "mysql.server_config", Status: "ok"},
		{TemplateID: "mysql.accounts", Status: "ok"},
	}
	mk := func(f facts.Fact) *facts.FactBundle {
		return sensBundleReceipts("db-mysql", coreOK, priv, f, accountFact("u1", "mysql.accounts", "app"))
	}
	base := map[string]string{"name": "lower_case_table_names", "value": "1"}
	badKind := facts.Fact{FactID: "c1", Kind: facts.FactPrivilege, Subject: "global",
		Status: facts.StatusObserved, Source: "mysql.server_config", Attributes: base}
	if s := findSnap(t, MatchSensitive(mk(badKind), lbl, nil), "l1"); s.Status != "unconfirmed" {
		t.Errorf("模式事实 Kind 不符：want unconfirmed, got %s", s.Status)
	}
	badStatus := facts.Fact{FactID: "c1", Kind: facts.FactAccountConfig, Subject: "global",
		Status: facts.StatusPermissionDenied, Source: "mysql.server_config", Attributes: base}
	if s := findSnap(t, MatchSensitive(mk(badStatus), lbl, nil), "l1"); s.Status != "unconfirmed" {
		t.Errorf("模式事实 Status 不符：want unconfirmed, got %s", s.Status)
	}
}

// 静态复核回归四轮：被授者三态——确认角色 / 确认用户 / 身份未知。
// 角色边缺失或被拒时，未知被授者不得直接当成确定用户。
func TestSensitiveGranteeIdentityThreeStates(t *testing.T) {
	grant := privFact("a1", "ora.sys_privs", "RPT_ROLE", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	lbl := []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	tabOK := facts.Receipt{TemplateID: "ora.tab_privs", Status: "ok"}
	sysOK := facts.Receipt{TemplateID: "ora.sys_privs", Status: "ok"}
	usersOK := facts.Receipt{TemplateID: "ora.users", Status: "ok"}
	// 零角色边 + 角色边来源被拒 → 未确认（不得把角色名当成用户暴露）。
	b := sensBundleReceipts("db-oracle",
		[]facts.Receipt{tabOK, sysOK, usersOK, {TemplateID: "ora.role_privs", Status: "denied"}}, grant)
	if s := findSnap(t, MatchSensitive(b, lbl, nil), "l1"); s.Status != "unconfirmed" {
		t.Errorf("零边+来源被拒：want unconfirmed, got %s", s.Status)
	}
	if n := countExposures(MatchSensitive(b, lbl, nil), "l1", false); n != 0 {
		t.Errorf("零边+来源被拒：不应有确定暴露，得到 %d", n)
	}
	// 零角色边 + 角色边来源缺收据 → 未确认。
	b = sensBundleReceipts("db-oracle", []facts.Receipt{tabOK, sysOK, usersOK}, grant)
	if s := findSnap(t, MatchSensitive(b, lbl, nil), "l1"); s.Status != "unconfirmed" {
		t.Errorf("零边+来源缺失：want unconfirmed, got %s", s.Status)
	}
	// 非 observed 边不识别角色 → 未确认。
	nonObsEdge := facts.Fact{Kind: facts.FactRoleEdge, Subject: "BOB",
		Status: facts.StatusPermissionDenied, Source: "ora.role_privs",
		PermissionPath: []string{"RPT_ROLE", "BOB"}, Activation: facts.ActivationDefault}
	b = sensBundleReceipts("db-oracle",
		[]facts.Receipt{tabOK, sysOK, usersOK, {TemplateID: "ora.role_privs", Status: "ok"}}, grant, nonObsEdge)
	if s := findSnap(t, MatchSensitive(b, lbl, nil), "l1"); s.Status != "unconfirmed" {
		t.Errorf("非 observed 边：want unconfirmed, got %s", s.Status)
	}
	// 确认的直接用户（用户清单事实 + 可信收据）→ 暴露。
	userGrant := privFact("a2", "ora.sys_privs", "APP_USER", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	b = sensBundleReceipts("db-oracle",
		[]facts.Receipt{tabOK, sysOK, usersOK, {TemplateID: "ora.role_privs", Status: "ok"}},
		userGrant, accountFact("u1", "ora.users", "APP_USER"))
	if s := findSnap(t, MatchSensitive(b, lbl, nil), "l1"); s.Status != "exposed" {
		t.Errorf("确认直接用户：want exposed, got %s", s.Status)
	}
	// 已确认角色、完整采集、无默认成员（仅非默认边）→ 无自动可达暴露。
	condEdge := roleEdgeFact("RPT_ROLE", "CAROL", facts.ActivationConditional)
	b = sensBundleReceipts("db-oracle",
		[]facts.Receipt{tabOK, sysOK, usersOK, {TemplateID: "ora.role_privs", Status: "ok"}}, grant, condEdge)
	sec := MatchSensitive(b, lbl, nil)
	if s := findSnap(t, sec, "l1"); s.Status != "no-broad-grant" {
		t.Errorf("确认角色无默认成员：want no-broad-grant, got %s", s.Status)
	}
	if n := countExposures(sec, "l1", false); n != 0 {
		t.Errorf("确认角色无默认成员：不应有暴露，得到 %d", n)
	}
	// MySQL：无清单事实的被授者 → 未确认；有清单事实 → 暴露。
	myGrant := privFact("m1", "mysql.db_privs", "ghost@%", "hisdb.*", map[string]string{"privilege": "SELECT"})
	myLbl := []SensitiveLabel{{ID: "l1", Database: "hisdb", Schema: "", Table: "patients", Category: "患者身份"}}
	myOK := []facts.Receipt{
		{TemplateID: "mysql.user_privs", Status: "ok"},
		{TemplateID: "mysql.global_grants", Status: "ok"},
		{TemplateID: "mysql.db_privs", Status: "ok"},
		{TemplateID: "mysql.accounts", Status: "ok"},
	}
	b = sensBundleReceipts("db-mysql", myOK, myGrant)
	if s := findSnap(t, MatchSensitive(b, myLbl, nil), "l1"); s.Status != "unconfirmed" {
		t.Errorf("MySQL 无清单事实：want unconfirmed, got %s", s.Status)
	}
	b = sensBundleReceipts("db-mysql", myOK, myGrant, accountFact("u1", "mysql.accounts", "ghost@%"))
	if s := findSnap(t, MatchSensitive(b, myLbl, nil), "l1"); s.Status != "exposed" {
		t.Errorf("MySQL 有清单事实：want exposed, got %s", s.Status)
	}
}

// 静态复核回归五轮：角色成员来源不完整时，不能断言无可达用户。
func TestSensitiveRoleMemberSourceIncomplete(t *testing.T) {
	grant := privFact("a1", "ora.sys_privs", "RPT_ROLE", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	condEdge := roleEdgeFact("RPT_ROLE", "CAROL", facts.ActivationConditional)
	lbl := []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	tabOK := facts.Receipt{TemplateID: "ora.tab_privs", Status: "ok"}
	sysOK := facts.Receipt{TemplateID: "ora.sys_privs", Status: "ok"}
	usersOK := facts.Receipt{TemplateID: "ora.users", Status: "ok"}
	// 角色已确认、仅非默认边、成员来源完整 → 无自动可达，不判未确认。
	b := sensBundleReceipts("db-oracle",
		[]facts.Receipt{tabOK, sysOK, usersOK, {TemplateID: "ora.role_privs", Status: "ok"}}, grant, condEdge)
	if s := findSnap(t, MatchSensitive(b, lbl, nil), "l1"); s.Status != "no-broad-grant" {
		t.Errorf("成员来源完整无默认成员：want no-broad-grant, got %s", s.Status)
	}
	// 成员来源 partial → 未确认（截断可能漏掉默认边）。
	b = sensBundleReceipts("db-oracle",
		[]facts.Receipt{tabOK, sysOK, usersOK, {TemplateID: "ora.role_privs", Status: "partial"}}, grant, condEdge)
	if s := findSnap(t, MatchSensitive(b, lbl, nil), "l1"); s.Status != "unconfirmed" {
		t.Errorf("成员来源 partial：want unconfirmed, got %s", s.Status)
	}
	// 成员来源 denied → 未确认。
	b = sensBundleReceipts("db-oracle",
		[]facts.Receipt{tabOK, sysOK, usersOK, {TemplateID: "ora.role_privs", Status: "denied"}}, grant, condEdge)
	if s := findSnap(t, MatchSensitive(b, lbl, nil), "l1"); s.Status != "unconfirmed" {
		t.Errorf("成员来源 denied：want unconfirmed, got %s", s.Status)
	}
}

// 静态复核回归五轮：多级角色传递展开——中间角色不是终点，只把确认用户作终点；
// 循环分支剪枝不死循环；不可信传递路径判未确认。
func TestSensitiveRoleTransitiveExpansion(t *testing.T) {
	grant := privFact("a1", "ora.sys_privs", "R_INNER", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	lbl := []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	rcs := []facts.Receipt{
		{TemplateID: "ora.tab_privs", Status: "ok"},
		{TemplateID: "ora.sys_privs", Status: "ok"},
		{TemplateID: "ora.role_privs", Status: "ok"},
		{TemplateID: "ora.users", Status: "ok"},
	}
	// R_INNER → R_OUTER → BOB：终点只应是 BOB（经链 R_INNER→R_OUTER），
	// 不得把中间角色 R_OUTER 报告成用户。
	b := sensBundleReceipts("db-oracle", rcs, grant,
		roleEdgeFact("R_INNER", "R_OUTER", facts.ActivationDefault),
		roleEdgeFact("R_OUTER", "BOB", facts.ActivationDefault),
		accountFact("u1", "ora.users", "BOB"))
	sec := MatchSensitive(b, lbl, nil)
	if s := findSnap(t, sec, "l1"); s.Status != "exposed" {
		t.Errorf("多级传递：want exposed, got %s", s.Status)
	}
	if n := countExposures(sec, "l1", false); n != 1 {
		t.Errorf("多级传递应恰好 1 条暴露，得到 %d", n)
	}
	for _, e := range sec.Exposures {
		if e.Subject == "R_OUTER" || !strings.Contains(e.Subject, "BOB") || !strings.Contains(e.Subject, "R_INNER→R_OUTER") {
			t.Errorf("多级传递终点应为 BOB 经链 R_INNER→R_OUTER，得到 %q", e.Subject)
		}
	}
	// 循环 R_A → R_B → R_A + R_B → BOB：剪枝后仍可达 BOB，不死循环。
	cycGrant := privFact("a2", "ora.sys_privs", "R_A", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	b = sensBundleReceipts("db-oracle", rcs, cycGrant,
		roleEdgeFact("R_A", "R_B", facts.ActivationDefault),
		roleEdgeFact("R_B", "R_A", facts.ActivationDefault),
		roleEdgeFact("R_B", "BOB", facts.ActivationDefault),
		accountFact("u1", "ora.users", "BOB"))
	sec = MatchSensitive(b, lbl, nil)
	if s := findSnap(t, sec, "l1"); s.Status != "exposed" {
		t.Errorf("循环传递：want exposed, got %s", s.Status)
	}
	if n := countExposures(sec, "l1", false); n != 1 {
		t.Errorf("循环传递应恰好 1 条暴露（BOB），得到 %d", n)
	}
	// 传递链含不可信边：R_INNER → R_OUTER（边来源被拒）→ BOB，BOB 不可达为确定暴露。
	b = sensBundleReceipts("db-oracle",
		[]facts.Receipt{
			{TemplateID: "ora.tab_privs", Status: "ok"},
			{TemplateID: "ora.sys_privs", Status: "ok"},
			{TemplateID: "ora.role_privs", Status: "ok"},
			{TemplateID: "ora.users", Status: "ok"},
			{TemplateID: "ora.cdb_role_privs", Status: "denied"},
		}, grant,
		roleEdgeFact("R_INNER", "R_OUTER", facts.ActivationDefault),
		facts.Fact{Kind: facts.FactRoleEdge, Subject: "BOB", Status: facts.StatusObserved,
			Source:         "ora.cdb_role_privs",
			PermissionPath: []string{"R_OUTER", "BOB"}, Activation: facts.ActivationDefault},
		accountFact("u1", "ora.users", "BOB"))
	if s := findSnap(t, MatchSensitive(b, lbl, nil), "l1"); s.Status != "unconfirmed" {
		t.Errorf("不可信传递链：want unconfirmed, got %s", s.Status)
	}
	if n := countExposures(MatchSensitive(b, lbl, nil), "l1", false); n != 0 {
		t.Errorf("不可信传递链不应有确定暴露，得到 %d", n)
	}
}

// 静态复核回归五轮：Oracle 引用标识符精确匹配——混合大小写用户与大写角色
// 并存时不得混淆；字典名不折叠。
func TestSensitiveOracleCaseSensitiveIdentity(t *testing.T) {
	lbl := []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	rcs := []facts.Receipt{
		{TemplateID: "ora.tab_privs", Status: "ok"},
		{TemplateID: "ora.sys_privs", Status: "ok"},
		{TemplateID: "ora.role_privs", Status: "ok"},
		{TemplateID: "ora.users", Status: "ok"},
	}
	// 混合大小写用户 App_User（引用名）为确认用户 → 暴露。
	userGrant := privFact("a1", "ora.sys_privs", "App_User", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	b := sensBundleReceipts("db-oracle", rcs, userGrant, accountFact("u1", "ora.users", "App_User"))
	if s := findSnap(t, MatchSensitive(b, lbl, nil), "l1"); s.Status != "exposed" {
		t.Errorf("混合大小写确认用户：want exposed, got %s", s.Status)
	}
	// 大写角色 APP_USER 经默认边到 BOB：终点为 BOB，不把 APP_USER 当用户。
	roleGrant := privFact("a2", "ora.sys_privs", "APP_USER", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	b = sensBundleReceipts("db-oracle", rcs, roleGrant,
		roleEdgeFact("APP_USER", "BOB", facts.ActivationDefault),
		accountFact("u1", "ora.users", "BOB"),
		accountFact("u2", "ora.users", "App_User"))
	sec := MatchSensitive(b, lbl, nil)
	if s := findSnap(t, sec, "l1"); s.Status != "exposed" {
		t.Errorf("大写角色传递：want exposed, got %s", s.Status)
	}
	for _, e := range sec.Exposures {
		if strings.Contains(e.Subject, "APP_USER") && !strings.Contains(e.Subject, "BOB") {
			t.Errorf("大写角色不得当成用户终点，得到 %q", e.Subject)
		}
	}
	// 反向混淆：授权给 App_User，但清单只有 APP_USER（且 APP_USER 为角色）→
	// App_User 既非该角色也非该用户，判未确认（不得折叠匹配）。
	b = sensBundleReceipts("db-oracle", rcs, userGrant,
		roleEdgeFact("APP_USER", "BOB", facts.ActivationDefault),
		accountFact("u1", "ora.users", "APP_USER"),
		accountFact("u2", "ora.users", "BOB"))
	if s := findSnap(t, MatchSensitive(b, lbl, nil), "l1"); s.Status != "unconfirmed" {
		t.Errorf("大小写不混淆：want unconfirmed, got %s", s.Status)
	}
}

// 静态复核回归六轮：成员采集 partial、已知成员全部豁免时，不得判“未发现”。
// 已知成员全部豁免的“无违规”结论依赖成员枚举完整；来源不完整可能漏掉
// 未采集的违规成员，故判未确认。
func TestSensitiveExemptMembersPartialCollection(t *testing.T) {
	grant := privFact("a1", "ora.sys_privs", "RPT_ROLE", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	edge := roleEdgeFact("RPT_ROLE", "BOB", facts.ActivationDefault)
	lbl := []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	bl := &rules.Baseline{Allows: []rules.BaselineAllow{
		{Subject: "BOB", Kind: "privilege", Value: "SELECT ANY TABLE", Scope: "instance"},
	}}
	mk := func(roleReceipt string) *facts.FactBundle {
		return sensBundleReceipts("db-oracle",
			[]facts.Receipt{
				{TemplateID: "ora.tab_privs", Status: "ok"},
				{TemplateID: "ora.sys_privs", Status: "ok"},
				{TemplateID: "ora.role_privs", Status: roleReceipt},
				{TemplateID: "ora.users", Status: "ok"},
			}, grant, edge, accountFact("u1", "ora.users", "BOB"))
	}
	// 成员来源完整、已知成员全部豁免 → no-broad-grant。
	sec := MatchSensitive(mk("ok"), lbl, bl)
	if s := findSnap(t, sec, "l1"); s.Status != "no-broad-grant" {
		t.Errorf("成员来源完整且全部豁免：want no-broad-grant, got %s", s.Status)
	}
	// 成员来源 partial、已知成员全部豁免 → 未确认（不得判“未发现”）。
	sec = MatchSensitive(mk("partial"), lbl, bl)
	if s := findSnap(t, sec, "l1"); s.Status != "unconfirmed" {
		t.Errorf("成员来源 partial 且全部豁免：want unconfirmed, got %s", s.Status)
	}
	if n := countExposures(sec, "l1", false); n != 0 {
		t.Errorf("成员来源 partial 且全部豁免：不应有违规暴露，得到 %d", n)
	}
	if n := countExposures(sec, "l1", true); n != 1 {
		t.Errorf("成员来源 partial 且全部豁免：应仍显示 1 条豁免暴露，得到 %d", n)
	}
	// 对照：成员来源 partial、已知成员不豁免 → 照常暴露（暴露优先）。
	sec = MatchSensitive(mk("partial"), lbl, nil)
	if s := findSnap(t, sec, "l1"); s.Status != "exposed" {
		t.Errorf("成员来源 partial 但有违规成员：want exposed, got %s", s.Status)
	}
	// MySQL 同口径。
	myGrant := privFact("m1", "mysql.db_privs", "rpt_role", "hisdb.*", map[string]string{"privilege": "SELECT"})
	myEdge := facts.Fact{Kind: facts.FactRoleEdge, Subject: "app@%", Status: facts.StatusObserved,
		Source:         "mysql.role_edges",
		PermissionPath: []string{"rpt_role", "app@%"}, Activation: facts.ActivationDefault}
	myLbl := []SensitiveLabel{{ID: "l1", Database: "hisdb", Schema: "", Table: "patients", Category: "患者身份"}}
	myBl := &rules.Baseline{Allows: []rules.BaselineAllow{
		{Subject: "app@%", Kind: "privilege", Value: "SELECT", Scope: "hisdb.*"},
	}}
	myMk := func(roleReceipt string) *facts.FactBundle {
		return sensBundleReceipts("db-mysql",
			[]facts.Receipt{
				{TemplateID: "mysql.user_privs", Status: "ok"},
				{TemplateID: "mysql.global_grants", Status: "ok"},
				{TemplateID: "mysql.db_privs", Status: "ok"},
				{TemplateID: "mysql.role_edges", Status: roleReceipt},
				{TemplateID: "mysql.accounts", Status: "ok"},
			}, myGrant, myEdge, accountFact("u1", "mysql.accounts", "app@%"))
	}
	sec = MatchSensitive(myMk("ok"), myLbl, myBl)
	if s := findSnap(t, sec, "l1"); s.Status != "no-broad-grant" {
		t.Errorf("MySQL 成员来源完整且全部豁免：want no-broad-grant, got %s", s.Status)
	}
	sec = MatchSensitive(myMk("partial"), myLbl, myBl)
	if s := findSnap(t, sec, "l1"); s.Status != "unconfirmed" {
		t.Errorf("MySQL 成员来源 partial 且全部豁免：want unconfirmed, got %s", s.Status)
	}
	// MySQL 对照：成员来源 partial、已知成员不豁免 → 照常暴露。
	sec = MatchSensitive(myMk("partial"), myLbl, nil)
	if s := findSnap(t, sec, "l1"); s.Status != "exposed" {
		t.Errorf("MySQL 成员来源 partial 但有违规成员：want exposed, got %s", s.Status)
	}
}

// 静态复核回归七轮：角色级豁免语义——基线放行授权角色本身时，覆盖该权限下
// 全部成员（已知与未采集），成员来源不完整也不判未确认，与零成员分支的
// 豁免 guard 统一；用户级豁免只覆盖已知用户本人（见上一个测试）。
func TestSensitiveRoleLevelExemptionCoversMembers(t *testing.T) {
	grant := privFact("a1", "ora.sys_privs", "RPT_ROLE", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	edge := roleEdgeFact("RPT_ROLE", "BOB", facts.ActivationDefault)
	lbl := []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	roleBl := &rules.Baseline{Allows: []rules.BaselineAllow{
		{Subject: "RPT_ROLE", Kind: "privilege", Value: "SELECT ANY TABLE", Scope: "instance"},
	}}
	mk := func(roleReceipt string) *facts.FactBundle {
		return sensBundleReceipts("db-oracle",
			[]facts.Receipt{
				{TemplateID: "ora.tab_privs", Status: "ok"},
				{TemplateID: "ora.sys_privs", Status: "ok"},
				{TemplateID: "ora.role_privs", Status: roleReceipt},
				{TemplateID: "ora.users", Status: "ok"},
			}, grant, edge, accountFact("u1", "ora.users", "BOB"))
	}
	// 角色级豁免 + 成员来源 partial：已知成员经角色豁免，未采集成员同属该
	// 角色覆盖范围 → no-broad-grant（不判未确认）。
	sec := MatchSensitive(mk("partial"), lbl, roleBl)
	if s := findSnap(t, sec, "l1"); s.Status != "no-broad-grant" {
		t.Errorf("角色级豁免 + 成员来源 partial：want no-broad-grant, got %s", s.Status)
	}
	if n := countExposures(sec, "l1", true); n != 1 {
		t.Errorf("角色级豁免 + 成员来源 partial：应显示 1 条豁免暴露，得到 %d", n)
	}
	// 零成员分支对照：角色级豁免 + 仅非默认边 + 成员来源 partial → 同样
	// no-broad-grant（豁免 guard 跳过疑似条目，与新分支统一）。
	condEdge := roleEdgeFact("RPT_ROLE", "CAROL", facts.ActivationConditional)
	b := sensBundleReceipts("db-oracle",
		[]facts.Receipt{
			{TemplateID: "ora.tab_privs", Status: "ok"},
			{TemplateID: "ora.sys_privs", Status: "ok"},
			{TemplateID: "ora.role_privs", Status: "partial"},
			{TemplateID: "ora.users", Status: "ok"},
		}, grant, condEdge)
	if s := findSnap(t, MatchSensitive(b, lbl, roleBl), "l1"); s.Status != "no-broad-grant" {
		t.Errorf("角色级豁免 + 零成员 + 成员来源 partial：want no-broad-grant, got %s", s.Status)
	}
	// MySQL 同口径：角色级豁免 + 成员来源 partial → no-broad-grant。
	myGrant := privFact("m1", "mysql.db_privs", "rpt_role", "hisdb.*", map[string]string{"privilege": "SELECT"})
	myEdge := facts.Fact{Kind: facts.FactRoleEdge, Subject: "app@%", Status: facts.StatusObserved,
		Source:         "mysql.role_edges",
		PermissionPath: []string{"rpt_role", "app@%"}, Activation: facts.ActivationDefault}
	myLbl := []SensitiveLabel{{ID: "l1", Database: "hisdb", Schema: "", Table: "patients", Category: "患者身份"}}
	myRoleBl := &rules.Baseline{Allows: []rules.BaselineAllow{
		{Subject: "rpt_role", Kind: "privilege", Value: "SELECT", Scope: "hisdb.*"},
	}}
	myB := sensBundleReceipts("db-mysql",
		[]facts.Receipt{
			{TemplateID: "mysql.user_privs", Status: "ok"},
			{TemplateID: "mysql.global_grants", Status: "ok"},
			{TemplateID: "mysql.db_privs", Status: "ok"},
			{TemplateID: "mysql.role_edges", Status: "partial"},
			{TemplateID: "mysql.accounts", Status: "ok"},
		}, myGrant, myEdge, accountFact("u1", "mysql.accounts", "app@%"))
	if s := findSnap(t, MatchSensitive(myB, myLbl, myRoleBl), "l1"); s.Status != "no-broad-grant" {
		t.Errorf("MySQL 角色级豁免 + 成员来源 partial：want no-broad-grant, got %s", s.Status)
	}
}

// 核心闭环事项 1：豁免语义负例——错主体、错权限、错 scope、中间角色豁免
// 均不豁免；用户级与角色级豁免在五种收据状态下的行为对照。
// 注意：本组只固定语义，不先断言代码已有误判；若用例失败即为真缺陷。
func TestSensitiveExemptionNegatives(t *testing.T) {
	lbl := []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	tabOK := facts.Receipt{TemplateID: "ora.tab_privs", Status: "ok"}
	sysOK := facts.Receipt{TemplateID: "ora.sys_privs", Status: "ok"}
	usersOK := facts.Receipt{TemplateID: "ora.users", Status: "ok"}
	grant := privFact("a1", "ora.sys_privs", "RPT_ROLE", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	edge := roleEdgeFact("RPT_ROLE", "BOB", facts.ActivationDefault)
	bob := accountFact("u1", "ora.users", "BOB")
	mkOra := func(roleReceipt string, fs ...facts.Fact) *facts.FactBundle {
		return sensBundleReceipts("db-oracle",
			[]facts.Receipt{tabOK, sysOK, usersOK, {TemplateID: "ora.role_privs", Status: roleReceipt}}, fs...)
	}
	allow := func(subject, value, scope string) *rules.Baseline {
		return &rules.Baseline{Allows: []rules.BaselineAllow{{Subject: subject, Kind: "privilege", Value: value, Scope: scope}}}
	}
	// 错主体（角色）：放行 OTHER_ROLE 不豁免 RPT_ROLE 的成员。
	if s := findSnap(t, MatchSensitive(mkOra("ok", grant, edge, bob), lbl, allow("OTHER_ROLE", "SELECT ANY TABLE", "instance")), "l1"); s.Status != "exposed" {
		t.Errorf("错主体（角色）：want exposed, got %s", s.Status)
	}
	// 错主体（用户）：直接授权 APP_USER，放行 BOB 不豁免。
	userGrant := privFact("a2", "ora.sys_privs", "APP_USER", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	b := mkOra("ok", userGrant, accountFact("u2", "ora.users", "APP_USER"))
	if s := findSnap(t, MatchSensitive(b, lbl, allow("BOB", "SELECT ANY TABLE", "instance")), "l1"); s.Status != "exposed" {
		t.Errorf("错主体（用户）：want exposed, got %s", s.Status)
	}
	// 错权限：放行 DELETE ANY TABLE 不豁免 SELECT ANY TABLE。
	if s := findSnap(t, MatchSensitive(mkOra("ok", grant, edge, bob), lbl, allow("RPT_ROLE", "DELETE ANY TABLE", "instance")), "l1"); s.Status != "exposed" {
		t.Errorf("错权限：want exposed, got %s", s.Status)
	}
	// 错 scope：放行范围 other 不豁免范围 instance 的授权。
	if s := findSnap(t, MatchSensitive(mkOra("ok", grant, edge, bob), lbl, allow("RPT_ROLE", "SELECT ANY TABLE", "other")), "l1"); s.Status != "exposed" {
		t.Errorf("错 scope：want exposed, got %s", s.Status)
	}
	// 中间角色豁免：放行 R_OUTER 不豁免经 R_INNER→R_OUTER 到达的 BOB
	// （豁免只看链首授权角色与用户本人）。
	innerGrant := privFact("a3", "ora.sys_privs", "R_INNER", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	b = mkOra("ok", innerGrant,
		roleEdgeFact("R_INNER", "R_OUTER", facts.ActivationDefault),
		roleEdgeFact("R_OUTER", "BOB", facts.ActivationDefault), bob)
	if s := findSnap(t, MatchSensitive(b, lbl, allow("R_OUTER", "SELECT ANY TABLE", "instance")), "l1"); s.Status != "exposed" {
		t.Errorf("中间角色豁免：want exposed, got %s", s.Status)
	}
	// 角色级豁免在成员来源 denied/缺失/冲突时仍覆盖 → no-broad-grant。
	roleBl := allow("RPT_ROLE", "SELECT ANY TABLE", "instance")
	if s := findSnap(t, MatchSensitive(mkOra("denied", grant, edge, bob), lbl, roleBl), "l1"); s.Status != "no-broad-grant" {
		t.Errorf("角色级豁免 + 成员来源 denied：want no-broad-grant, got %s", s.Status)
	}
	b = sensBundleReceipts("db-oracle", []facts.Receipt{tabOK, sysOK, usersOK}, grant, edge, bob)
	if s := findSnap(t, MatchSensitive(b, lbl, roleBl), "l1"); s.Status != "no-broad-grant" {
		t.Errorf("角色级豁免 + 成员来源缺失：want no-broad-grant, got %s", s.Status)
	}
	b = sensBundleReceipts("db-oracle",
		[]facts.Receipt{tabOK, sysOK, usersOK, {TemplateID: "ora.role_privs", Status: "ok"}, {TemplateID: "ora.role_privs", Status: "denied"}},
		grant, edge, bob)
	if s := findSnap(t, MatchSensitive(b, lbl, roleBl), "l1"); s.Status != "no-broad-grant" {
		t.Errorf("角色级豁免 + 成员来源冲突：want no-broad-grant, got %s", s.Status)
	}
	// 用户级豁免在成员来源 denied/缺失/冲突时不覆盖 → 未确认。
	userBl := allow("BOB", "SELECT ANY TABLE", "instance")
	if s := findSnap(t, MatchSensitive(mkOra("denied", grant, edge, bob), lbl, userBl), "l1"); s.Status != "unconfirmed" {
		t.Errorf("用户级豁免 + 成员来源 denied：want unconfirmed, got %s", s.Status)
	}
	b = sensBundleReceipts("db-oracle", []facts.Receipt{tabOK, sysOK, usersOK}, grant, edge, bob)
	if s := findSnap(t, MatchSensitive(b, lbl, userBl), "l1"); s.Status != "unconfirmed" {
		t.Errorf("用户级豁免 + 成员来源缺失：want unconfirmed, got %s", s.Status)
	}
	b = sensBundleReceipts("db-oracle",
		[]facts.Receipt{tabOK, sysOK, usersOK, {TemplateID: "ora.role_privs", Status: "ok"}, {TemplateID: "ora.role_privs", Status: "denied"}},
		grant, edge, bob)
	if s := findSnap(t, MatchSensitive(b, lbl, userBl), "l1"); s.Status != "unconfirmed" {
		t.Errorf("用户级豁免 + 成员来源冲突：want unconfirmed, got %s", s.Status)
	}

	// MySQL 同口径负例。
	myLbl := []SensitiveLabel{{ID: "l1", Database: "hisdb", Schema: "", Table: "patients", Category: "患者身份"}}
	myGrant := privFact("m1", "mysql.db_privs", "rpt_role", "hisdb.*", map[string]string{"privilege": "SELECT"})
	myEdge := func(role, member string) facts.Fact {
		return facts.Fact{Kind: facts.FactRoleEdge, Subject: member, Status: facts.StatusObserved,
			Source:         "mysql.role_edges",
			PermissionPath: []string{role, member}, Activation: facts.ActivationDefault}
	}
	myAcct := accountFact("u1", "mysql.accounts", "app@%")
	mkMy := func(roleReceipt string, fs ...facts.Fact) *facts.FactBundle {
		return sensBundleReceipts("db-mysql",
			[]facts.Receipt{
				{TemplateID: "mysql.user_privs", Status: "ok"},
				{TemplateID: "mysql.global_grants", Status: "ok"},
				{TemplateID: "mysql.db_privs", Status: "ok"},
				{TemplateID: "mysql.role_edges", Status: roleReceipt},
				{TemplateID: "mysql.accounts", Status: "ok"},
			}, fs...)
	}
	if s := findSnap(t, MatchSensitive(mkMy("ok", myGrant, myEdge("rpt_role", "app@%"), myAcct), myLbl, allow("other_role", "SELECT", "hisdb.*")), "l1"); s.Status != "exposed" {
		t.Errorf("MySQL 错主体：want exposed, got %s", s.Status)
	}
	insGrant := privFact("m2", "mysql.db_privs", "rpt_role", "hisdb.*", map[string]string{"privilege": "INSERT"})
	if s := findSnap(t, MatchSensitive(mkMy("ok", insGrant, myEdge("rpt_role", "app@%"), myAcct), myLbl, allow("rpt_role", "SELECT", "hisdb.*")), "l1"); s.Status != "exposed" {
		t.Errorf("MySQL 错权限：want exposed, got %s", s.Status)
	}
	if s := findSnap(t, MatchSensitive(mkMy("ok", myGrant, myEdge("rpt_role", "app@%"), myAcct), myLbl, allow("rpt_role", "SELECT", "otherdb.*")), "l1"); s.Status != "exposed" {
		t.Errorf("MySQL 错 scope：want exposed, got %s", s.Status)
	}
	innerMyGrant := privFact("m3", "mysql.db_privs", "inner_role", "hisdb.*", map[string]string{"privilege": "SELECT"})
	b = mkMy("ok", innerMyGrant, myEdge("inner_role", "mid_role"), myEdge("mid_role", "app@%"), myAcct)
	if s := findSnap(t, MatchSensitive(b, myLbl, allow("mid_role", "SELECT", "hisdb.*")), "l1"); s.Status != "exposed" {
		t.Errorf("MySQL 中间角色豁免：want exposed, got %s", s.Status)
	}
	if s := findSnap(t, MatchSensitive(mkMy("denied", myGrant, myEdge("rpt_role", "app@%"), myAcct), myLbl, allow("rpt_role", "SELECT", "hisdb.*")), "l1"); s.Status != "no-broad-grant" {
		t.Errorf("MySQL 角色级豁免 + 成员来源 denied：want no-broad-grant, got %s", s.Status)
	}
	if s := findSnap(t, MatchSensitive(mkMy("denied", myGrant, myEdge("rpt_role", "app@%"), myAcct), myLbl, allow("app@%", "SELECT", "hisdb.*")), "l1"); s.Status != "unconfirmed" {
		t.Errorf("MySQL 用户级豁免 + 成员来源 denied：want unconfirmed, got %s", s.Status)
	}
}

// 核心闭环事项 2：空 scope 现状固定——基线 scope 为空或事实 scope 为空，
// 任一为空即匹配（通配语义）。本轮不收紧，只固定现状并在界面与文档提示。
func TestBaselineEmptyScopeBehavior(t *testing.T) {
	// 规则层单元口径。
	bl := &rules.Baseline{Allows: []rules.BaselineAllow{{Subject: "R", Kind: "privilege", Value: "P", Scope: ""}}}
	if !bl.Allowed("R", "privilege", "P", "instance") {
		t.Errorf("基线 scope 为空应匹配任意事实范围")
	}
	if !bl.Allowed("R", "privilege", "P", "") {
		t.Errorf("双方 scope 均为空应匹配")
	}
	bl2 := &rules.Baseline{Allows: []rules.BaselineAllow{{Subject: "R", Kind: "privilege", Value: "P", Scope: "instance"}}}
	if !bl2.Allowed("R", "privilege", "P", "") {
		t.Errorf("事实 scope 为空应匹配任意基线范围（现状通配）")
	}
	if bl2.Allowed("R", "privilege", "P", "other") {
		t.Errorf("双方 scope 非空且不同不应匹配")
	}
	if bl2.Allowed("OTHER", "privilege", "P", "instance") {
		t.Errorf("主体不同不应匹配")
	}
	// 端到端：基线 scope 留空 + Oracle 授权 → 豁免。
	lbl := []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	grant := privFact("a1", "ora.sys_privs", "APP_USER", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	b := sensBundleReceipts("db-oracle",
		[]facts.Receipt{
			{TemplateID: "ora.tab_privs", Status: "ok"},
			{TemplateID: "ora.sys_privs", Status: "ok"},
			{TemplateID: "ora.users", Status: "ok"},
		}, grant, accountFact("u1", "ora.users", "APP_USER"))
	emptyScopeBl := &rules.Baseline{Allows: []rules.BaselineAllow{{Subject: "APP_USER", Kind: "privilege", Value: "SELECT ANY TABLE", Scope: ""}}}
	if s := findSnap(t, MatchSensitive(b, lbl, emptyScopeBl), "l1"); s.Status != "no-broad-grant" {
		t.Errorf("基线 scope 留空端到端：want no-broad-grant, got %s", s.Status)
	}
	// 端到端：事实 scope 为空 + 基线 scope 有值 → 同样匹配（现状通配）。
	noScopeGrant := privFact("a2", "ora.sys_privs", "APP_USER", "", map[string]string{"privilege": "SELECT ANY TABLE"})
	b = sensBundleReceipts("db-oracle",
		[]facts.Receipt{
			{TemplateID: "ora.tab_privs", Status: "ok"},
			{TemplateID: "ora.sys_privs", Status: "ok"},
			{TemplateID: "ora.users", Status: "ok"},
		}, noScopeGrant, accountFact("u1", "ora.users", "APP_USER"))
	scopedBl := &rules.Baseline{Allows: []rules.BaselineAllow{{Subject: "APP_USER", Kind: "privilege", Value: "SELECT ANY TABLE", Scope: "instance"}}}
	if s := findSnap(t, MatchSensitive(b, lbl, scopedBl), "l1"); s.Status != "no-broad-grant" {
		t.Errorf("事实 scope 为空端到端：want no-broad-grant, got %s", s.Status)
	}
}

// 核心闭环事项 3：零成员且角色整体豁免时，报告必须留下豁免记录——
// 授权角色、权限、范围、事实 ID 与豁免依据，不编造用户可达性。
func TestSensitiveZeroMemberRoleExemptionRecord(t *testing.T) {
	lbl := []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	grant := privFact("a9", "ora.sys_privs", "RPT_ROLE", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	condEdge := roleEdgeFact("RPT_ROLE", "CAROL", facts.ActivationConditional)
	roleBl := &rules.Baseline{Allows: []rules.BaselineAllow{{Subject: "RPT_ROLE", Kind: "privilege", Value: "SELECT ANY TABLE", Scope: "instance"}}}
	mk := func(roleReceipt string) *facts.FactBundle {
		return sensBundleReceipts("db-oracle",
			[]facts.Receipt{
				{TemplateID: "ora.tab_privs", Status: "ok"},
				{TemplateID: "ora.sys_privs", Status: "ok"},
				{TemplateID: "ora.role_privs", Status: roleReceipt},
				{TemplateID: "ora.users", Status: "ok"},
			}, grant, condEdge)
	}
	for _, rcs := range []string{"ok", "partial"} {
		sec := MatchSensitive(mk(rcs), lbl, roleBl)
		s := findSnap(t, sec, "l1")
		if s.Status != "no-broad-grant" {
			t.Errorf("零成员角色豁免(%s)：want no-broad-grant, got %s", rcs, s.Status)
		}
		var rec *SensitiveExposure
		for i := range sec.Exposures {
			if sec.Exposures[i].Subject == "RPT_ROLE" && sec.Exposures[i].Exempt {
				rec = &sec.Exposures[i]
			}
		}
		if rec == nil {
			t.Fatalf("零成员角色豁免(%s)：应有角色豁免记录条目", rcs)
		}
		if len(rec.Evidence) != 1 || rec.Evidence[0] != "a9" {
			t.Errorf("零成员角色豁免(%s)：证据应为事实 a9，得到 %v", rcs, rec.Evidence)
		}
		for _, want := range []string{"角色整体豁免", "RPT_ROLE", "SELECT ANY TABLE", "instance", "不编造"} {
			if !strings.Contains(rec.Note, want) {
				t.Errorf("零成员角色豁免(%s)：备注应含 %q，得到 %q", rcs, want, rec.Note)
			}
		}
		if n := countExposures(sec, "l1", false); n != 0 {
			t.Errorf("零成员角色豁免(%s)：不应有违规暴露，得到 %d", rcs, n)
		}
	}
	// MySQL 同口径。
	myLbl := []SensitiveLabel{{ID: "l1", Database: "hisdb", Schema: "", Table: "patients", Category: "患者身份"}}
	myGrant := privFact("m9", "mysql.db_privs", "rpt_role", "hisdb.*", map[string]string{"privilege": "SELECT"})
	myEdge := facts.Fact{Kind: facts.FactRoleEdge, Subject: "carol@%", Status: facts.StatusObserved,
		Source:         "mysql.role_edges",
		PermissionPath: []string{"rpt_role", "carol@%"}, Activation: facts.ActivationConditional}
	myBl := &rules.Baseline{Allows: []rules.BaselineAllow{{Subject: "rpt_role", Kind: "privilege", Value: "SELECT", Scope: "hisdb.*"}}}
	myB := sensBundleReceipts("db-mysql",
		[]facts.Receipt{
			{TemplateID: "mysql.user_privs", Status: "ok"},
			{TemplateID: "mysql.global_grants", Status: "ok"},
			{TemplateID: "mysql.db_privs", Status: "ok"},
			{TemplateID: "mysql.role_edges", Status: "ok"},
			{TemplateID: "mysql.accounts", Status: "ok"},
		}, myGrant, myEdge)
	sec := MatchSensitive(myB, myLbl, myBl)
	if s := findSnap(t, sec, "l1"); s.Status != "no-broad-grant" {
		t.Errorf("MySQL 零成员角色豁免：want no-broad-grant, got %s", s.Status)
	}
	found := false
	for _, e := range sec.Exposures {
		if e.Subject == "rpt_role" && e.Exempt && len(e.Evidence) == 1 && e.Evidence[0] == "m9" {
			found = true
		}
	}
	if !found {
		t.Errorf("MySQL 零成员角色豁免：应有角色豁免记录条目（证据 m9）")
	}
}

// 覆盖边界（如实标注）：本测试只覆盖 MatchSensitive 评估→加豁免→内存 JSON
// 快照重解析→Word 渲染；持久化基线增删、GenerateReport 生成、旧报告重读
// 见 TestSensitivePersistedBaselineAndReportReread；Web 组件渲染未覆盖，
// 本测试不作为完整端到端验收。
func TestSensitiveExemptionReportSectionFlow(t *testing.T) {
	lbl := []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	grant := privFact("a1", "ora.sys_privs", "RPT_ROLE", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	edge := roleEdgeFact("RPT_ROLE", "BOB", facts.ActivationDefault)
	b := sensBundleReceipts("db-oracle",
		[]facts.Receipt{
			{TemplateID: "ora.tab_privs", Status: "ok"},
			{TemplateID: "ora.sys_privs", Status: "ok"},
			{TemplateID: "ora.role_privs", Status: "ok"},
			{TemplateID: "ora.users", Status: "ok"},
		}, grant, edge, accountFact("u1", "ora.users", "BOB"))
	// 评估（无豁免）：暴露。
	secA := MatchSensitive(b, lbl, nil)
	if s := findSnap(t, secA, "l1"); s.Status != "exposed" {
		t.Fatalf("流程评估：want exposed, got %s", s.Status)
	}
	if n := countExposures(secA, "l1", false); n != 1 {
		t.Fatalf("流程评估：应有 1 条违规暴露，得到 %d", n)
	}
	// 生成报告（快照化）：旧报告内容此后不再改写。
	snapA, err := json.Marshal(secA)
	if err != nil {
		t.Fatalf("快照序列化失败：%v", err)
	}
	// 添加豁免（用户级）：不再违规，豁免条目带证据。
	userBl := &rules.Baseline{Allows: []rules.BaselineAllow{{Subject: "BOB", Kind: "privilege", Value: "SELECT ANY TABLE", Scope: "instance"}}}
	secB := MatchSensitive(b, lbl, userBl)
	if s := findSnap(t, secB, "l1"); s.Status != "no-broad-grant" {
		t.Fatalf("流程加豁免：want no-broad-grant, got %s", s.Status)
	}
	if n := countExposures(secB, "l1", true); n != 1 {
		t.Fatalf("流程加豁免：应有 1 条豁免条目，得到 %d", n)
	}
	// Word 渲染豁免后报告：事实 ID 与豁免标记应出现在文档中。
	doc, err := RenderReportDocx(`{"sensitive":`+string(mustJSON(t, secB))+`}`, "r-flow")
	if err != nil {
		t.Fatalf("Word 渲染失败：%v", err)
	}
	if xml := docxText(t, doc); !strings.Contains(xml, "a1") || !strings.Contains(xml, "已放行") {
		t.Errorf("Word 豁免报告应含事实 ID a1 与已放行标记")
	}
	// 撤销豁免 → 再评估：恢复暴露。
	secC := MatchSensitive(b, lbl, nil)
	if s := findSnap(t, secC, "l1"); s.Status != "exposed" {
		t.Fatalf("流程撤销豁免：want exposed, got %s", s.Status)
	}
	// 核对内存快照：重解析结论不变（非落库旧报告重读，见持久化测试）。
	var old SensitiveSection
	if err := json.Unmarshal(snapA, &old); err != nil {
		t.Fatalf("旧快照解析失败：%v", err)
	}
	if s := findSnap(t, &old, "l1"); s.Status != "exposed" {
		t.Errorf("旧报告快照应仍为 exposed，得到 %s", s.Status)
	}
	if n := countExposures(&old, "l1", false); n != 1 {
		t.Errorf("旧报告快照应仍有 1 条违规条目，得到 %d", n)
	}
	// 零成员角色豁免报告的 Word 渲染：记录条目事实 ID 与豁免备注应出现。
	zeroGrant := privFact("a9", "ora.sys_privs", "RPT_ROLE", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	condEdge := roleEdgeFact("RPT_ROLE", "CAROL", facts.ActivationConditional)
	zb := sensBundleReceipts("db-oracle",
		[]facts.Receipt{
			{TemplateID: "ora.tab_privs", Status: "ok"},
			{TemplateID: "ora.sys_privs", Status: "ok"},
			{TemplateID: "ora.role_privs", Status: "ok"},
			{TemplateID: "ora.users", Status: "ok"},
		}, zeroGrant, condEdge)
	roleBl := &rules.Baseline{Allows: []rules.BaselineAllow{{Subject: "RPT_ROLE", Kind: "privilege", Value: "SELECT ANY TABLE", Scope: "instance"}}}
	secZ := MatchSensitive(zb, lbl, roleBl)
	doc, err = RenderReportDocx(`{"sensitive":`+string(mustJSON(t, secZ))+`}`, "r-zero")
	if err != nil {
		t.Fatalf("Word 零成员报告渲染失败：%v", err)
	}
	if xml := docxText(t, doc); !strings.Contains(xml, "a9") || !strings.Contains(xml, "角色整体豁免") {
		t.Errorf("Word 零成员报告应含事实 ID a9 与角色整体豁免备注")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("JSON 序列化失败：%v", err)
	}
	return b
}

// docxText 解包 docx 并返回 document.xml 文本（渲染断言用）。
func docxText(t *testing.T, doc []byte) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		t.Fatalf("docx 解包失败：%v", err)
	}
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("document.xml 打开失败：%v", err)
			}
			defer rc.Close()
			data, err := io.ReadAll(rc)
			if err != nil {
				t.Fatalf("document.xml 读取失败：%v", err)
			}
			return string(data)
		}
	}
	t.Fatalf("docx 中未找到 word/document.xml")
	return ""
}

// 复审跟进（PR #17 draft 复审意见 1）：角色授权事实可信、角色级豁免匹配，
// 但成员关系收据为 denied、缺失或冲突时，结论 no-broad-grant 仍须输出原
// 授权事实与豁免依据，备注明示“授权已豁免、成员可达性未确认”，不编造成员。
func TestSensitiveRoleExemptionUnprovenMemberRecord(t *testing.T) {
	lbl := []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	grant := privFact("a1", "ora.sys_privs", "RPT_ROLE", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	edge := roleEdgeFact("RPT_ROLE", "BOB", facts.ActivationDefault)
	bob := accountFact("u1", "ora.users", "BOB")
	roleBl := &rules.Baseline{Allows: []rules.BaselineAllow{{Subject: "RPT_ROLE", Kind: "privilege", Value: "SELECT ANY TABLE", Scope: "instance"}}}
	base := []facts.Receipt{
		{TemplateID: "ora.tab_privs", Status: "ok"},
		{TemplateID: "ora.sys_privs", Status: "ok"},
		{TemplateID: "ora.users", Status: "ok"},
	}
	cases := []struct {
		name string
		rcs  []facts.Receipt
	}{
		{"denied", append(append([]facts.Receipt{}, base...), facts.Receipt{TemplateID: "ora.role_privs", Status: "denied"})},
		{"missing", base},
		{"conflict", append(append([]facts.Receipt{}, base...),
			facts.Receipt{TemplateID: "ora.role_privs", Status: "ok"},
			facts.Receipt{TemplateID: "ora.role_privs", Status: "denied"})},
	}
	for _, c := range cases {
		sec := MatchSensitive(sensBundleReceipts("db-oracle", c.rcs, grant, edge, bob), lbl, roleBl)
		s := findSnap(t, sec, "l1")
		if s.Status != "no-broad-grant" {
			t.Errorf("Oracle 角色豁免 + 成员来源 %s：want no-broad-grant, got %s", c.name, s.Status)
		}
		var rec *SensitiveExposure
		for i := range sec.Exposures {
			if sec.Exposures[i].Subject == "RPT_ROLE" && sec.Exposures[i].Exempt {
				rec = &sec.Exposures[i]
			}
			if sec.Exposures[i].Subject == "BOB" {
				t.Errorf("Oracle 角色豁免 + 成员来源 %s：不应编造用户 BOB 的条目", c.name)
			}
		}
		if rec == nil {
			t.Fatalf("Oracle 角色豁免 + 成员来源 %s：应有角色豁免记录条目", c.name)
		}
		if len(rec.Evidence) != 1 || rec.Evidence[0] != "a1" {
			t.Errorf("Oracle 角色豁免 + 成员来源 %s：证据应为事实 a1，得到 %v", c.name, rec.Evidence)
		}
		for _, want := range []string{"成员可达性未确认", "RPT_ROLE", "SELECT ANY TABLE", "instance", "不编造"} {
			if !strings.Contains(rec.Note, want) {
				t.Errorf("Oracle 角色豁免 + 成员来源 %s：备注应含 %q，得到 %q", c.name, want, rec.Note)
			}
		}
		if n := countExposures(sec, "l1", false); n != 0 {
			t.Errorf("Oracle 角色豁免 + 成员来源 %s：不应有违规暴露，得到 %d", c.name, n)
		}
	}
	// MySQL 同型。
	myLbl := []SensitiveLabel{{ID: "l1", Database: "hisdb", Schema: "", Table: "patients", Category: "患者身份"}}
	myGrant := privFact("m1", "mysql.db_privs", "rpt_role", "hisdb.*", map[string]string{"privilege": "SELECT"})
	myEdge := facts.Fact{Kind: facts.FactRoleEdge, Subject: "app@%", Status: facts.StatusObserved,
		Source:         "mysql.role_edges",
		PermissionPath: []string{"rpt_role", "app@%"}, Activation: facts.ActivationDefault}
	myAcct := accountFact("u1", "mysql.accounts", "app@%")
	myBl := &rules.Baseline{Allows: []rules.BaselineAllow{{Subject: "rpt_role", Kind: "privilege", Value: "SELECT", Scope: "hisdb.*"}}}
	myBase := []facts.Receipt{
		{TemplateID: "mysql.user_privs", Status: "ok"},
		{TemplateID: "mysql.global_grants", Status: "ok"},
		{TemplateID: "mysql.db_privs", Status: "ok"},
		{TemplateID: "mysql.accounts", Status: "ok"},
	}
	myCases := []struct {
		name string
		rcs  []facts.Receipt
	}{
		{"denied", append(append([]facts.Receipt{}, myBase...), facts.Receipt{TemplateID: "mysql.role_edges", Status: "denied"})},
		{"missing", myBase},
		{"conflict", append(append([]facts.Receipt{}, myBase...),
			facts.Receipt{TemplateID: "mysql.role_edges", Status: "ok"},
			facts.Receipt{TemplateID: "mysql.role_edges", Status: "denied"})},
	}
	for _, c := range myCases {
		sec := MatchSensitive(sensBundleReceipts("db-mysql", c.rcs, myGrant, myEdge, myAcct), myLbl, myBl)
		s := findSnap(t, sec, "l1")
		if s.Status != "no-broad-grant" {
			t.Errorf("MySQL 角色豁免 + 成员来源 %s：want no-broad-grant, got %s", c.name, s.Status)
		}
		found := false
		for _, e := range sec.Exposures {
			if e.Subject == "rpt_role" && e.Exempt && len(e.Evidence) == 1 && e.Evidence[0] == "m1" &&
				strings.Contains(e.Note, "成员可达性未确认") {
				found = true
			}
			if e.Subject == "app@%" {
				t.Errorf("MySQL 角色豁免 + 成员来源 %s：不应编造用户 app@%% 的条目", c.name)
			}
		}
		if !found {
			t.Errorf("MySQL 角色豁免 + 成员来源 %s：应有角色豁免记录条目（证据 m1，备注含成员可达性未确认）", c.name)
		}
	}
}

// 复审跟进（PR #17 draft 复审意见 2）：持久化层面的豁免闭环——基线增删、
// GenerateReport 生成、旧报告重读均走真实落库行；Web 组件渲染仍未覆盖，
// 本测试不作为完整端到端验收。
func TestSensitivePersistedBaselineAndReportReread(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "sens.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := CreateHospital(db, "h-test", "测试医院"); err != nil {
		t.Fatal(err)
	}
	if err := CreateAsset(db, Asset{ID: "a-ora", HospitalID: "h-test", Kind: "db-oracle", Name: "测试 Oracle"}); err != nil {
		t.Fatal(err)
	}
	// 成员来源 denied 的包：授权事实可信，边不可信。
	b := sensBundleReceipts("db-oracle",
		[]facts.Receipt{
			{TemplateID: "ora.tab_privs", Status: "ok"},
			{TemplateID: "ora.sys_privs", Status: "ok"},
			{TemplateID: "ora.role_privs", Status: "denied"},
			{TemplateID: "ora.users", Status: "ok"},
		},
		privFact("a1", "ora.sys_privs", "RPT_ROLE", "instance", map[string]string{"privilege": "SELECT ANY TABLE"}),
		roleEdgeFact("RPT_ROLE", "BOB", facts.ActivationDefault),
		accountFact("u1", "ora.users", "BOB"))
	if _, err := db.Exec(`INSERT INTO collection_plans (id, hospital_id, name, profile, spec, created_by)
		VALUES ('p1', 'h-test', 'P1', 'prof', '{}', 'web')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO fact_bundles (id, plan_id, hospital_id, asset_id, schema_version, adapter, execution, bundle, imported_at)
		VALUES ('bundle-1', 'p1', 'h-test', 'a-ora', '1', 'db-oracle', 'COMPLETE', ?, '2026-11-04 10:00:00')`, string(mustJSON(t, b))); err != nil {
		t.Fatal(err)
	}
	if _, err := UpsertSensitiveLabel(db, "db-oracle", "admin", SensitiveLabel{
		Hospital: "h-test", Asset: "a-ora", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}); err != nil {
		t.Fatal(err)
	}
	sensitiveOf := func(reportID string) *SensitiveSection {
		t.Helper()
		snap, err := GetReportSnapshot(db, reportID)
		if err != nil {
			t.Fatal(err)
		}
		var parsed struct {
			Sensitive *SensitiveSection `json:"sensitive"`
		}
		if err := json.Unmarshal([]byte(snap), &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed.Sensitive == nil {
			t.Fatalf("报告 %s 应含敏感对象节", reportID)
		}
		return parsed.Sensitive
	}
	// 无基线：成员可达性未确认（非暴露、非“未发现”）。
	repA, err := GenerateReport(db, "h-test", "p1", "bundle-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	secA := sensitiveOf(repA)
	// 标签 ID 由落库生成，按唯一标签行断言。
	if len(secA.Labels) != 1 || secA.Labels[0].Status != "unconfirmed" {
		t.Fatalf("无基线报告：标签应为 unconfirmed，实际 %+v", secA.Labels)
	}
	// 持久化基线新增 → 再生成报告：角色豁免记录出现，结论 no-broad-grant。
	if err := CreateBaseline(db, "bl-1", "h-test", "db-oracle",
		[]rules.BaselineAllow{{Subject: "RPT_ROLE", Kind: "privilege", Value: "SELECT ANY TABLE", Scope: "instance"}}, "admin"); err != nil {
		t.Fatal(err)
	}
	repB, err := GenerateReport(db, "h-test", "p1", "bundle-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	secB := sensitiveOf(repB)
	if len(secB.Labels) != 1 || secB.Labels[0].Status != "no-broad-grant" {
		t.Fatalf("加基线报告：标签应为 no-broad-grant，实际 %+v", secB.Labels)
	}
	found := false
	for _, e := range secB.Exposures {
		if e.Subject == "RPT_ROLE" && e.Exempt && len(e.Evidence) == 1 && e.Evidence[0] == "a1" &&
			strings.Contains(e.Note, "成员可达性未确认") {
			found = true
		}
	}
	if !found {
		t.Errorf("加基线报告：应有角色豁免记录条目（证据 a1，备注含成员可达性未确认），实际 %+v", secB.Exposures)
	}
	// 持久化基线删除 → 再生成报告：恢复未确认。
	if err := DeleteBaseline(db, "bl-1"); err != nil {
		t.Fatal(err)
	}
	repC, err := GenerateReport(db, "h-test", "p1", "bundle-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	secC := sensitiveOf(repC)
	if len(secC.Labels) != 1 || secC.Labels[0].Status != "unconfirmed" {
		t.Fatalf("删基线报告：标签应恢复 unconfirmed，实际 %+v", secC.Labels)
	}
	// 旧报告重读：报告 A 快照不被 B、C 污染。
	secOld := sensitiveOf(repA)
	if len(secOld.Labels) != 1 || secOld.Labels[0].Status != "unconfirmed" {
		t.Fatalf("旧报告 A 重读：标签应仍为 unconfirmed，实际 %+v", secOld.Labels)
	}
	// 撤销豁免后重读已豁免的报告 B：结论与事实 ID 仍不变。
	secOldB := sensitiveOf(repB)
	if len(secOldB.Labels) != 1 || secOldB.Labels[0].Status != "no-broad-grant" {
		t.Fatalf("旧报告 B 重读：标签应仍为 no-broad-grant，实际 %+v", secOldB.Labels)
	}
	foundB := false
	for _, e := range secOldB.Exposures {
		if e.Subject == "RPT_ROLE" && e.Exempt && len(e.Evidence) == 1 && e.Evidence[0] == "a1" &&
			strings.Contains(e.Note, "成员可达性未确认") {
			foundB = true
		}
	}
	if !foundB {
		t.Errorf("旧报告 B 重读：豁免记录条目（证据 a1）应保持不变，实际 %+v", secOldB.Exposures)
	}
}

// 复审跟进（PR #17 draft 复审意见，2027ddc 后）：成员采集被拒后完全没有
// 返回角色边时，被授者身份无法确认；即使原授权匹配豁免，也须留下授权
// 事实与豁免依据，记录“被授者授权已豁免、身份及可达性未确认”，不猜它
// 是角色还是用户。
func TestSensitiveUnknownGranteeExemptionRecord(t *testing.T) {
	lbl := []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	grant := privFact("a1", "ora.sys_privs", "RPT_ROLE", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	roleBl := &rules.Baseline{Allows: []rules.BaselineAllow{{Subject: "RPT_ROLE", Kind: "privilege", Value: "SELECT ANY TABLE", Scope: "instance"}}}
	base := []facts.Receipt{
		{TemplateID: "ora.tab_privs", Status: "ok"},
		{TemplateID: "ora.sys_privs", Status: "ok"},
		{TemplateID: "ora.users", Status: "ok"},
	}
	cases := []struct {
		name string
		rcs  []facts.Receipt
	}{
		{"denied", append(append([]facts.Receipt{}, base...), facts.Receipt{TemplateID: "ora.role_privs", Status: "denied"})},
		{"missing", base},
		{"conflict", append(append([]facts.Receipt{}, base...),
			facts.Receipt{TemplateID: "ora.role_privs", Status: "ok"},
			facts.Receipt{TemplateID: "ora.role_privs", Status: "denied"})},
	}
	for _, c := range cases {
		// 零边：无任何角色边事实、无用户事实。
		sec := MatchSensitive(sensBundleReceipts("db-oracle", c.rcs, grant), lbl, roleBl)
		s := findSnap(t, sec, "l1")
		if s.Status != "no-broad-grant" {
			t.Errorf("Oracle 未知被授者豁免 + 收据 %s：want no-broad-grant, got %s", c.name, s.Status)
		}
		var rec *SensitiveExposure
		for i := range sec.Exposures {
			if sec.Exposures[i].Subject == "RPT_ROLE" && sec.Exposures[i].Exempt {
				rec = &sec.Exposures[i]
			}
		}
		if rec == nil {
			t.Fatalf("Oracle 未知被授者豁免 + 收据 %s：应有豁免记录条目", c.name)
		}
		if len(rec.Evidence) != 1 || rec.Evidence[0] != "a1" {
			t.Errorf("Oracle 未知被授者豁免 + 收据 %s：证据应为事实 a1，得到 %v", c.name, rec.Evidence)
		}
		for _, want := range []string{"被授者授权已豁免、身份及可达性未确认", "不猜它是角色还是用户", "RPT_ROLE", "SELECT ANY TABLE", "instance"} {
			if !strings.Contains(rec.Note, want) {
				t.Errorf("Oracle 未知被授者豁免 + 收据 %s：备注应含 %q，得到 %q", c.name, want, rec.Note)
			}
		}
		if strings.Contains(rec.Note, "角色整体豁免") {
			t.Errorf("Oracle 未知被授者豁免 + 收据 %s：备注不应断言它是角色", c.name)
		}
		if n := countExposures(sec, "l1", false); n != 0 {
			t.Errorf("Oracle 未知被授者豁免 + 收据 %s：不应有违规暴露，得到 %d", c.name, n)
		}
		// 非豁免对照：零边 + 无基线仍为未确认（疑似，不进确定暴露表）。
		sec2 := MatchSensitive(sensBundleReceipts("db-oracle", c.rcs, grant), lbl, nil)
		if s := findSnap(t, sec2, "l1"); s.Status != "unconfirmed" {
			t.Errorf("Oracle 未知被授者无豁免 + 收据 %s：want unconfirmed, got %s", c.name, s.Status)
		}
		if n := countExposures(sec2, "l1", true); n != 0 {
			t.Errorf("Oracle 未知被授者无豁免 + 收据 %s：确定暴露表应为空，得到 %d", c.name, n)
		}
	}
	// MySQL 同型。
	myLbl := []SensitiveLabel{{ID: "l1", Database: "hisdb", Schema: "", Table: "patients", Category: "患者身份"}}
	myGrant := privFact("m1", "mysql.db_privs", "rpt_role", "hisdb.*", map[string]string{"privilege": "SELECT"})
	myBl := &rules.Baseline{Allows: []rules.BaselineAllow{{Subject: "rpt_role", Kind: "privilege", Value: "SELECT", Scope: "hisdb.*"}}}
	myBase := []facts.Receipt{
		{TemplateID: "mysql.user_privs", Status: "ok"},
		{TemplateID: "mysql.global_grants", Status: "ok"},
		{TemplateID: "mysql.db_privs", Status: "ok"},
		{TemplateID: "mysql.accounts", Status: "ok"},
	}
	myCases := []struct {
		name string
		rcs  []facts.Receipt
	}{
		{"denied", append(append([]facts.Receipt{}, myBase...), facts.Receipt{TemplateID: "mysql.role_edges", Status: "denied"})},
		{"missing", myBase},
		{"conflict", append(append([]facts.Receipt{}, myBase...),
			facts.Receipt{TemplateID: "mysql.role_edges", Status: "ok"},
			facts.Receipt{TemplateID: "mysql.role_edges", Status: "denied"})},
	}
	for _, c := range myCases {
		sec := MatchSensitive(sensBundleReceipts("db-mysql", c.rcs, myGrant), myLbl, myBl)
		s := findSnap(t, sec, "l1")
		if s.Status != "no-broad-grant" {
			t.Errorf("MySQL 未知被授者豁免 + 收据 %s：want no-broad-grant, got %s", c.name, s.Status)
		}
		found := false
		for _, e := range sec.Exposures {
			if e.Subject == "rpt_role" && e.Exempt && len(e.Evidence) == 1 && e.Evidence[0] == "m1" &&
				strings.Contains(e.Note, "被授者授权已豁免、身份及可达性未确认") &&
				strings.Contains(e.Note, "不猜它是角色还是用户") {
				found = true
			}
		}
		if !found {
			t.Errorf("MySQL 未知被授者豁免 + 收据 %s：应有豁免记录条目（证据 m1，备注含身份及可达性未确认）", c.name)
		}
	}
}

// 复审跟进：未证实原因的第二成因——收据正常、成员身份未知（边指向未登
// 记主体）时，豁免记录备注须用涵盖表述，不得只写收据不可信。
func TestSensitiveUnprovenUnknownIdentityRecord(t *testing.T) {
	lbl := []SensitiveLabel{{ID: "l1", Schema: "HIS", Table: "PATIENTS", Category: "患者身份"}}
	grant := privFact("a1", "ora.sys_privs", "RPT_ROLE", "instance", map[string]string{"privilege": "SELECT ANY TABLE"})
	ghostEdge := roleEdgeFact("RPT_ROLE", "GHOST", facts.ActivationDefault)
	roleBl := &rules.Baseline{Allows: []rules.BaselineAllow{{Subject: "RPT_ROLE", Kind: "privilege", Value: "SELECT ANY TABLE", Scope: "instance"}}}
	b := sensBundleReceipts("db-oracle",
		[]facts.Receipt{
			{TemplateID: "ora.tab_privs", Status: "ok"},
			{TemplateID: "ora.sys_privs", Status: "ok"},
			{TemplateID: "ora.role_privs", Status: "ok"},
			{TemplateID: "ora.users", Status: "ok"},
		}, grant, ghostEdge)
	sec := MatchSensitive(b, lbl, roleBl)
	if s := findSnap(t, sec, "l1"); s.Status != "no-broad-grant" {
		t.Fatalf("Oracle 身份未知成因：want no-broad-grant, got %s", s.Status)
	}
	found := false
	for _, e := range sec.Exposures {
		if e.Subject == "RPT_ROLE" && e.Exempt && strings.Contains(e.Note, "成员身份未知") &&
			strings.Contains(e.Note, "成员可达性未确认") {
			found = true
		}
		if e.Subject == "GHOST" {
			t.Errorf("Oracle 身份未知成因：不应把未登记主体 GHOST 当成确定用户条目")
		}
	}
	if !found {
		t.Errorf("Oracle 身份未知成因：应有豁免记录条目（备注含成员身份未知与成员可达性未确认）")
	}
	// MySQL 同型。
	myLbl := []SensitiveLabel{{ID: "l1", Database: "hisdb", Schema: "", Table: "patients", Category: "患者身份"}}
	myGrant := privFact("m1", "mysql.db_privs", "rpt_role", "hisdb.*", map[string]string{"privilege": "SELECT"})
	myEdge := facts.Fact{Kind: facts.FactRoleEdge, Subject: "ghost@%", Status: facts.StatusObserved,
		Source:         "mysql.role_edges",
		PermissionPath: []string{"rpt_role", "ghost@%"}, Activation: facts.ActivationDefault}
	myBl := &rules.Baseline{Allows: []rules.BaselineAllow{{Subject: "rpt_role", Kind: "privilege", Value: "SELECT", Scope: "hisdb.*"}}}
	myB := sensBundleReceipts("db-mysql",
		[]facts.Receipt{
			{TemplateID: "mysql.user_privs", Status: "ok"},
			{TemplateID: "mysql.global_grants", Status: "ok"},
			{TemplateID: "mysql.db_privs", Status: "ok"},
			{TemplateID: "mysql.role_edges", Status: "ok"},
			{TemplateID: "mysql.accounts", Status: "ok"},
		}, myGrant, myEdge)
	sec = MatchSensitive(myB, myLbl, myBl)
	if s := findSnap(t, sec, "l1"); s.Status != "no-broad-grant" {
		t.Fatalf("MySQL 身份未知成因：want no-broad-grant, got %s", s.Status)
	}
	found = false
	for _, e := range sec.Exposures {
		if e.Subject == "rpt_role" && e.Exempt && strings.Contains(e.Note, "成员身份未知") {
			found = true
		}
	}
	if !found {
		t.Errorf("MySQL 身份未知成因：应有豁免记录条目（备注含成员身份未知）")
	}
}
