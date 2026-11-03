package platform

import (
	"database/sql"
	"encoding/json"
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
	b := sensBundleReceipts("db-oracle",
		[]facts.Receipt{{TemplateID: "ora.tab_privs", Status: "ok"}, {TemplateID: "ora.sys_privs", Status: "ok"}, {TemplateID: "ora.container", Status: "ok"}},
		fact, containerFact("pdb1"))
	b.Scope.Container = "orclservice"
	if s := findSnap(t, MatchSensitive(b, lbl("pdb1"), nil), "l1"); s.Status != "exposed" {
		t.Errorf("service≠PDB 但事实一致：want exposed, got %s", s.Status)
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
		fact, containerFact("pdb1"))
	if s := findSnap(t, MatchSensitive(b, lbl("pdb1"), nil), "l1"); s.Status != "unconfirmed" {
		t.Errorf("容器收据失败：want unconfirmed, got %s", s.Status)
	}
	// 容器事实与标签不符 → 未确认。
	b = sensBundleReceipts("db-oracle",
		[]facts.Receipt{{TemplateID: "ora.tab_privs", Status: "ok"}, {TemplateID: "ora.sys_privs", Status: "ok"}, {TemplateID: "ora.container", Status: "ok"}},
		fact, containerFact("pdb2"))
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
	// 边可信 → 暴露（经角色）。
	b = sensBundleReceipts("db-oracle",
		[]facts.Receipt{tabOK, sysOK, {TemplateID: "ora.role_privs", Status: "ok"}}, grant, edge)
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
