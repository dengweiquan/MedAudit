package platform

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"medaudit/internal/facts"
	"medaudit/internal/rules"
)

// M5-5 敏感对象最小闭环（表级优先，列级显式提示未覆盖）。
//
// 只存对象标识与敏感类别，不存真实患者数据。标签在报告生成时点快照
// （含 version），标签改删只影响以后生成的报告，已存报告快照不变义。
// 匹配只用已采集事实，不新增采集模板；未标记不等于不敏感，
// 缺授权事实不等于安全——两条在报告节中明示。

// SensitiveLabel 一条敏感对象标记。自然键 = 医院/资产/库/模式/表/列。
type SensitiveLabel struct {
	ID       string `json:"id"`
	Hospital string `json:"hospital_id"`
	Asset    string `json:"asset_id"`
	Database string `json:"database"` // 容器/库：Oracle PDB、MySQL/PG/MSSQL 库名；空 = 该资产默认库
	Schema   string `json:"schema"`
	Table    string `json:"table"`
	Column   string `json:"column"` // 空 = 表级；非空 = 列级（事实为表级，列级粒度未覆盖）
	Category string `json:"category"`
	Version  int    `json:"version"`
	Created  string `json:"created_at"`
	Updated  string `json:"updated_at"`
}

// SensitiveLabelSnap 报告快照中的标签行（生成时点版本）。
type SensitiveLabelSnap struct {
	ID       string `json:"id"`
	Database string `json:"database"`
	Schema   string `json:"schema"`
	Table    string `json:"table"`
	Column   string `json:"column"`
	Category string `json:"category"`
	Version  int    `json:"version"`
	// Status：exposed（有 broad 授权可达）、no-broad-grant（本包事实中未发现
	// broad 授权，不等于安全）、unconfirmed（事实不足以确认，如 MSSQL 对象未采集）。
	Status string   `json:"status"`
	Notes  []string `json:"notes,omitempty"`
}

// SensitiveExposure 一条确定的 broad 授权暴露（风险按策略升级为 high：
// ANY 的基础规则为 medium，对象被标记敏感后升级；PUBLIC 本已是 high）。
type SensitiveExposure struct {
	LabelID   string   `json:"label_id"`
	Object    string   `json:"object"`  // 展示用：库.模式.表（列级时附列）
	Kind      string   `json:"kind"`    // public / any / global / database-wide
	Subject   string   `json:"subject"` // 被授者；角色传递时为“用户（经角色）”
	Privilege string   `json:"privilege"`
	Evidence  []string `json:"evidence"` // 原始授权事实 ID（可追溯）
	Risk      string   `json:"risk"`
	Exempt    bool     `json:"exempt"` // 基线放行（合法豁免，不计入违规暴露）
	Note      string   `json:"note,omitempty"`
}

// SensitiveSection 报告中的敏感对象节。
type SensitiveSection struct {
	Labels    []SensitiveLabelSnap `json:"labels"`
	Exposures []SensitiveExposure  `json:"exposures"`
	Notes     []string             `json:"notes"`
}

// NormalizeIdentifier 按数据库标识符规则规范化一个名字：去空白；双引号包裹
// 视为引用标识符（去引号、保留原大小写）；Oracle 未引用转大写，PG 未引用
// 转小写，MySQL/MSSQL 原样保留（匹配时不区分大小写，见 matchName）。
func NormalizeIdentifier(adapter facts.TargetType, name string) string {
	name = strings.TrimSpace(name)
	quoted := len(name) >= 2 && strings.HasPrefix(name, `"`) && strings.HasSuffix(name, `"`)
	if quoted {
		return name[1 : len(name)-1]
	}
	switch adapter {
	case facts.TargetDBOracle:
		return strings.ToUpper(name)
	case facts.TargetDBPostgres:
		return strings.ToLower(name)
	default:
		return name
	}
}

// matchName 比较事实侧名字与标签侧名字：Oracle/PG 已在写入时规范化，
// 精确比较；MySQL/MSSQL 按排序规则通常不区分大小写，用 EqualFold。
func matchName(adapter facts.TargetType, fact, label string) bool {
	switch adapter {
	case facts.TargetDBOracle, facts.TargetDBPostgres:
		return fact == label
	default:
		return strings.EqualFold(fact, label)
	}
}

// newLabelID 生成标签 ID（sl- + 16 位随机十六进制）。
func newLabelID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("sl-%d", time.Now().UnixNano())
	}
	return "sl-" + hex.EncodeToString(b[:])
}

// ListSensitiveLabels 列出某医院某资产的全部标记（asset 为空时列医院全部）。
func ListSensitiveLabels(db *sql.DB, hospitalID, assetID string) ([]SensitiveLabel, error) {
	q := `SELECT id, hospital_id, asset_id, database_name, schema_name, table_name,
		column_name, category, version, created_at, updated_at
		FROM sensitive_labels WHERE hospital_id = ?`
	args := []any{hospitalID}
	if assetID != "" {
		q += ` AND asset_id = ?`
		args = append(args, assetID)
	}
	q += ` ORDER BY database_name, schema_name, table_name, column_name`
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SensitiveLabel
	for rows.Next() {
		var l SensitiveLabel
		if err := rows.Scan(&l.ID, &l.Hospital, &l.Asset, &l.Database, &l.Schema,
			&l.Table, &l.Column, &l.Category, &l.Version, &l.Created, &l.Updated); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// UpsertSensitiveLabel 创建或幂等更新一条标记：自然键已存在时，类别相同
// 返回原行（不升版本），类别不同更新类别并 version +1。写入前按资产类型
// 规范化标识符。返回最终行。hospital/asset 归属由调用方（handler）校验。
func UpsertSensitiveLabel(db *sql.DB, adapter facts.TargetType, createdBy string, l SensitiveLabel) (SensitiveLabel, error) {
	l.Database = strings.TrimSpace(l.Database)
	l.Schema = NormalizeIdentifier(adapter, l.Schema)
	l.Table = NormalizeIdentifier(adapter, l.Table)
	l.Column = NormalizeIdentifier(adapter, l.Column)
	if l.Table == "" {
		return l, fmt.Errorf("表名不能为空")
	}
	// MySQL 的模式即库：库名与模式名至少其一非空即可；其余库模式名必填。
	if l.Schema == "" && !(adapter == facts.TargetDBMySQL && l.Database != "") {
		return l, fmt.Errorf("模式名不能为空")
	}
	if strings.TrimSpace(l.Category) == "" {
		return l, fmt.Errorf("敏感类别不能为空")
	}
	l.Category = strings.TrimSpace(l.Category)
	var existing SensitiveLabel
	err := db.QueryRow(`SELECT id, category, version, created_at, updated_at FROM sensitive_labels
		WHERE hospital_id = ? AND asset_id = ? AND database_name = ? AND schema_name = ?
		AND table_name = ? AND column_name = ?`,
		l.Hospital, l.Asset, l.Database, l.Schema, l.Table, l.Column).
		Scan(&existing.ID, &existing.Category, &existing.Version, &existing.Created, &existing.Updated)
	if err == nil {
		if existing.Category == l.Category {
			existing.Hospital, existing.Asset = l.Hospital, l.Asset
			existing.Database, existing.Schema, existing.Table, existing.Column = l.Database, l.Schema, l.Table, l.Column
			return existing, nil
		}
		if _, err := db.Exec(`UPDATE sensitive_labels SET category = ?, version = version + 1,
			updated_at = CURRENT_TIMESTAMP WHERE id = ?`, l.Category, existing.ID); err != nil {
			return l, err
		}
	}
	if err != nil && err != sql.ErrNoRows {
		return l, err
	}
	if err == sql.ErrNoRows {
		l.ID = newLabelID()
		if _, err := db.Exec(`INSERT INTO sensitive_labels
			(id, hospital_id, asset_id, database_name, schema_name, table_name, column_name,
			category, version, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
			l.ID, l.Hospital, l.Asset, l.Database, l.Schema, l.Table, l.Column, l.Category, createdBy); err != nil {
			return l, err
		}
	}
	var out SensitiveLabel
	err = db.QueryRow(`SELECT id, hospital_id, asset_id, database_name, schema_name, table_name,
		column_name, category, version, created_at, updated_at FROM sensitive_labels
		WHERE hospital_id = ? AND asset_id = ? AND database_name = ? AND schema_name = ?
		AND table_name = ? AND column_name = ?`,
		l.Hospital, l.Asset, l.Database, l.Schema, l.Table, l.Column).
		Scan(&out.ID, &out.Hospital, &out.Asset, &out.Database, &out.Schema, &out.Table,
			&out.Column, &out.Category, &out.Version, &out.Created, &out.Updated)
	return out, err
}

// UpdateSensitiveLabelCategory 只改类别（名字是标识，改名 = 删后重建），version +1。
func UpdateSensitiveLabelCategory(db *sql.DB, id, category string) (SensitiveLabel, error) {
	if strings.TrimSpace(category) == "" {
		return SensitiveLabel{}, fmt.Errorf("敏感类别不能为空")
	}
	res, err := db.Exec(`UPDATE sensitive_labels SET category = ?, version = version + 1,
		updated_at = CURRENT_TIMESTAMP WHERE id = ?`, strings.TrimSpace(category), id)
	if err != nil {
		return SensitiveLabel{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return SensitiveLabel{}, err
	}
	if n == 0 {
		return SensitiveLabel{}, sql.ErrNoRows
	}
	var l SensitiveLabel
	err = db.QueryRow(`SELECT id, hospital_id, asset_id, database_name, schema_name, table_name,
		column_name, category, version, created_at, updated_at FROM sensitive_labels WHERE id = ?`, id).
		Scan(&l.ID, &l.Hospital, &l.Asset, &l.Database, &l.Schema, &l.Table, &l.Column,
			&l.Category, &l.Version, &l.Created, &l.Updated)
	return l, err
}

// DeleteSensitiveLabel 删除一条标记（返回是否命中）。
func DeleteSensitiveLabel(db *sql.DB, id string) (bool, error) {
	res, err := db.Exec(`DELETE FROM sensitive_labels WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ---- 匹配引擎（只用已采集事实） ----

// dataPrivileges 数据读写权限（MySQL 全局/库级可达判定用；DDL 权限
// CREATE/DROP/ALTER 属另一类风险，不计入数据暴露）。
var dataPrivileges = map[string]bool{
	"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true,
}

// isTableANY 是否为表级 ANY 权限（Oracle）：SELECT/INSERT/UPDATE/DELETE/
// ALTER/DROP/FLASHBACK ANY TABLE 与旧式 ANY TABLE。SYS 模式不在 ANY 可达
// 范围内（数据字典保护，O7_DICTIONARY_ACCESSIBILITY 默认 FALSE；
// 若现场改为 TRUE，SYS 亦可达——见报告注记）。
func isTableANY(priv string) bool {
	p := strings.ToUpper(strings.TrimSpace(priv))
	return p == "ANY TABLE" || strings.Contains(p, " ANY TABLE")
}

// roleResolution 从角色边与身份清单事实建解析表：roles 为全部角色名（边
// PermissionPath[0]），defaultUsers 为角色 → 默认激活用户，
// credibleDefaultUsers 为其中边来源可信的默认用户，users 为已确认用户
// （身份清单事实中的账号，且清单来源收据可信）。
// 角色与用户共用命名空间：出现在边中的名字即角色；角色权限只通过
// 默认激活边到达用户，非默认角色需 SET ROLE 激活，不计入自动可达。
// 边逐条验收据：边事实的来源收据被拒/失败/缺失/冲突时，该边不可信——
// 角色授权本身可显示，但实际用户可达性不得作为确定暴露。
type roleResolution struct {
	roles                map[string]bool
	defaultUsers         map[string][]string
	credibleDefaultUsers map[string][]string
	users                map[string]bool
}

// identityKey 身份清单键：Oracle 用户名按大写折叠（字典存储惯例），
// MySQL 账号为 user@host 全量匹配；其余类型无清单，返回空键。
func identityKey(adapter facts.TargetType, subject string) string {
	switch adapter {
	case facts.TargetDBOracle:
		return "ora:" + strings.ToUpper(subject)
	case facts.TargetDBMySQL:
		return "mysql:" + subject
	default:
		return ""
	}
}

func resolveRoles(b *facts.FactBundle) roleResolution {
	r := roleResolution{roles: map[string]bool{}, defaultUsers: map[string][]string{}, credibleDefaultUsers: map[string][]string{}, users: map[string]bool{}}
	for _, f := range b.Facts {
		if f.Kind != facts.FactRoleEdge || f.Status != facts.StatusObserved || len(f.PermissionPath) == 0 {
			continue
		}
		role := f.PermissionPath[0]
		r.roles[role] = true
		if f.Activation == facts.ActivationDefault {
			r.defaultUsers[role] = append(r.defaultUsers[role], f.Subject)
			if sensitiveSourceCredible(b, f.Source) {
				r.credibleDefaultUsers[role] = append(r.credibleDefaultUsers[role], f.Subject)
			}
		}
	}
	// 已确认用户：身份清单事实（Oracle ora.users/ora.cdb_users、MySQL
	// mysql.accounts）中已观察的配置事实，且清单来源收据可信。
	for _, f := range b.Facts {
		if f.Kind != facts.FactAccountConfig || f.Status != facts.StatusObserved {
			continue
		}
		switch f.Source {
		case "ora.users", "ora.cdb_users", "mysql.accounts":
		default:
			continue
		}
		if key := identityKey(b.Collector.Adapter, f.Subject); key != "" && sensitiveSourceCredible(b, f.Source) {
			r.users[key] = true
		}
	}
	return r
}

// expandGrantee 三态展开被授者：
//   - 已确认角色 → 按默认边展开（可信边用户 / 不可信边用户），isRole=true；
//   - 已确认用户 → 本人，isRole=false；
//   - 身份未知 → unknown=true，不展开：角色边缺失/被拒且无可信用户清单时，
//     不得把未知被授者直接当成确定用户（角色采集被拒、根本没有返回边时，
//     角色名会被误当成用户暴露）。
func (r roleResolution) expandGrantee(adapter facts.TargetType, subject string) (credible, uncredible []string, isRole, unknown bool) {
	if r.roles[subject] {
		cred := map[string]bool{}
		for _, u := range r.credibleDefaultUsers[subject] {
			cred[u] = true
		}
		for _, u := range r.defaultUsers[subject] {
			if !cred[u] {
				uncredible = append(uncredible, u)
			}
		}
		return r.credibleDefaultUsers[subject], uncredible, true, false
	}
	if r.users[identityKey(adapter, subject)] {
		return []string{subject}, nil, false, false
	}
	return nil, nil, false, true
}

// hasPrivilegeFacts 包中是否存在授权事实（无则无法判定暴露面）。
func hasPrivilegeFacts(b *facts.FactBundle) bool {
	for _, f := range b.Facts {
		if f.Kind == facts.FactPrivilege && f.Status == facts.StatusObserved {
			return true
		}
	}
	return false
}

// MatchSensitive 对一批标签做 broad 授权匹配，返回报告节。
// baseline 为 nil 时不做豁免标记；豁免只按事实被授者（角色传递时角色或用户
// 任一放行即豁免）判定，与评估口径一致。
// sensitiveSourceComplete 某授权来源的收据是否完整：收据须存在且状态 ok、
// 未截断。缺失/被拒/失败/截断都算不完整——不能据此声称“未发现 broad 授权”。
func sensitiveSourceComplete(b *facts.FactBundle, source string) (bool, string) {
	var saw bool
	for _, rc := range b.Receipts {
		if rc.TemplateID != source {
			continue
		}
		saw = true
		if rc.Status != "ok" || rc.Truncated {
			if rc.Truncated && rc.Status == "ok" {
				return false, "truncated"
			}
			return false, rc.Status
		}
	}
	if !saw {
		return false, "missing"
	}
	return true, "ok"
}

// sensitiveSourceCredible 某授权来源的事实是否可信：收据存在且状态为 ok 或
// partial（采集实际读到了数据，观察到的授权事实可信），且同来源无冲突收据。
// 收据被拒/失败/缺失时，该来源的 observed 事实不能作为确定暴露证据
// （可能是残留或不可信快照）；同来源同时有 ok 与 denied/failed 时，事实无法
// 绑定到某一次执行，保守不采信（与顺序无关）；partial 加可信命中可以报告，
// 没有可信来源则未确认。
func sensitiveSourceCredible(b *facts.FactBundle, source string) bool {
	sawOK := false
	for _, rc := range b.Receipts {
		if rc.TemplateID != source {
			continue
		}
		switch rc.Status {
		case "ok", "partial":
			sawOK = true
		case "denied", "failed":
			return false
		}
	}
	return sawOK
}

// sensitiveOracleContainer 指定库名标签的可信容器身份：只认新采集器的
// ora.container 事实（服务端 SYS_CONTEXT CON_NAME，Kind 为配置事实且已观察）
// 加可信收据。旧包无此事实（Scope.Container 是连接服务名，不可信），探针失败
// 时事实缺失或收据不可信——均不得据 Scope 判定归属；服务名与 PDB 名可能不同，
// 服务名即使与标签库名相同也不作数。
func sensitiveOracleContainer(b *facts.FactBundle, database string) (bool, string) {
	if !sensitiveSourceCredible(b, "ora.container") {
		return false, "标签指定了库名（" + database + "），但本包无可信容器身份（旧包无 ora.container 事实，或容器探针失败），无法确认标签归属，不作跨容器匹配。"
	}
	for _, f := range b.Facts {
		if f.Source != "ora.container" || f.Kind != facts.FactAccountConfig || f.Status != facts.StatusObserved {
			continue
		}
		if strings.EqualFold(f.Attributes["con_name"], database) {
			return true, ""
		}
	}
	return false, "标签库名（" + database + "）与本包可信容器身份不符或未采集到容器事实，不作跨容器匹配；请以该库的资产包复评。"
}

// sensitiveSourcesComplete 该资产类型相关授权来源是否全部完整。
// Oracle：tab_privs + sys_privs 必备；cdb_sys_privs 仅当包内有该来源的
// 事实或收据时才要求（非 CDB 无此来源，不强求）。
// PG：object_privileges 必备。MySQL：user_privs + global_grants + db_privs 必备。
// MSSQL：对象级事实从未采集，恒为不完整（匹配分支直接置未确认）。
func sensitiveSourcesComplete(b *facts.FactBundle, adapter facts.TargetType) (bool, []string) {
	var core, conditional []string
	switch adapter {
	case facts.TargetDBOracle:
		core = []string{"ora.tab_privs", "ora.sys_privs"}
		conditional = []string{"ora.cdb_sys_privs"}
	case facts.TargetDBPostgres:
		core = []string{"pg.object_privileges"}
	case facts.TargetDBMySQL:
		core = []string{"mysql.user_privs", "mysql.global_grants", "mysql.db_privs"}
	default:
		return false, []string{"对象级授权来源未采集"}
	}
	var incomplete []string
	for _, src := range core {
		if ok, state := sensitiveSourceComplete(b, src); !ok {
			incomplete = append(incomplete, src+"（"+state+"）")
		}
	}
	for _, src := range conditional {
		present := false
		for _, f := range b.Facts {
			if f.Source == src {
				present = true
				break
			}
		}
		if !present {
			for _, rc := range b.Receipts {
				if rc.TemplateID == src {
					present = true
					break
				}
			}
		}
		if present {
			if ok, state := sensitiveSourceComplete(b, src); !ok {
				incomplete = append(incomplete, src+"（"+state+"）")
			}
		}
	}
	return len(incomplete) == 0, incomplete
}

func MatchSensitive(b *facts.FactBundle, labels []SensitiveLabel, baseline *rules.Baseline) *SensitiveSection {
	var adapter facts.TargetType
	if b != nil {
		adapter = b.Collector.Adapter
	}
	sec := &SensitiveSection{
		Labels:    []SensitiveLabelSnap{},
		Exposures: []SensitiveExposure{},
		Notes: []string{
			"未标记不等于不敏感：本节只覆盖已标记对象，未标记对象不在此判定。",
		},
	}
	if b == nil {
		sec.Notes = append(sec.Notes, "事实包缺失，无法判定暴露面。")
		return sec
	}
	if !hasPrivilegeFacts(b) {
		sec.Notes = append(sec.Notes, "本包未采集到授权事实，无法判定暴露面；缺授权事实不等于安全。")
	}
	if b.Execution == "PARTIAL" {
		sec.Notes = append(sec.Notes, "采集不完整（PARTIAL），暴露面可能低估。")
	}
	// MySQL 库名大小写：按包内 lower_case_table_names 事实（0 → 区分，
	// 1/2 → 不区分）；事实本身须有可信收据（mysql.server_config ok/partial）
	// 背书，否则模式仍未知。模式未知时：库名精确相等仍可匹配；仅大小写不同
	// 的授权无法确认是否匹配（不计命中，也不判不匹配，见标签不定注记）。
	mysqlCaseSensitive, mysqlCaseKnown := true, false
	if adapter == facts.TargetDBMySQL {
		configCredible := sensitiveSourceCredible(b, "mysql.server_config")
		for _, f := range b.Facts {
			if f.Source != "mysql.server_config" || f.Kind != facts.FactAccountConfig ||
				f.Status != facts.StatusObserved || f.Attributes["name"] != "lower_case_table_names" {
				continue
			}
			if !configCredible {
				break
			}
			switch strings.TrimSpace(f.Attributes["value"]) {
			case "1", "2":
				mysqlCaseSensitive, mysqlCaseKnown = false, true
			case "0":
				mysqlCaseSensitive, mysqlCaseKnown = true, true
			}
			break
		}
		if !mysqlCaseKnown {
			sec.Notes = append(sec.Notes, "MySQL 实例 lower_case_table_names 未采集或无可信收据，库名大小写模式未知：库名精确相等仍可匹配，仅大小写不同的授权无法确认是否匹配（见标签注记）。")
		}
	}
	matchMySQLDB := func(a, b string) bool {
		if mysqlCaseSensitive {
			return a == b
		}
		return strings.EqualFold(a, b)
	}
	roles := resolveRoles(b)
	// 事实按来源分桶，避免每标签全量扫描重复判定。
	var (
		oraTab, oraSys []facts.Fact
		pgObj          []facts.Fact
		myPriv         []facts.Fact
		mssqlPerm      []facts.Fact
	)
	for _, f := range b.Facts {
		if f.Kind != facts.FactPrivilege || f.Status != facts.StatusObserved {
			continue
		}
		switch f.Source {
		case "ora.tab_privs":
			oraTab = append(oraTab, f)
		case "ora.sys_privs", "ora.cdb_sys_privs":
			oraSys = append(oraSys, f)
		case "pg.object_privileges":
			pgObj = append(pgObj, f)
		case "mysql.user_privs", "mysql.global_grants", "mysql.db_privs":
			myPriv = append(myPriv, f)
		case "mssql.db_permissions":
			mssqlPerm = append(mssqlPerm, f)
		}
	}
	exempt := func(subject, priv, scope string) bool {
		return baseline != nil && baseline.Allowed(subject, "privilege", priv, scope)
	}
	for _, l := range labels {
		snap := SensitiveLabelSnap{
			ID: l.ID, Database: l.Database, Schema: l.Schema, Table: l.Table,
			Column: l.Column, Category: l.Category, Version: l.Version,
			Status: "no-broad-grant",
		}
		display := l.Database + "." + l.Schema + "." + l.Table
		if l.Database == "" {
			display = l.Schema + "." + l.Table
		}
		if l.Column != "" {
			display += "(" + l.Column + ")"
			snap.Notes = append(snap.Notes,
				"列级标记：现有事实为表级粒度，列级授权未采集；表级 broad 授权可达该列时仍计暴露，列级专属授权无法确认。")
		}
		var labelExposures []SensitiveExposure
		var labelCredible []bool // 与 labelExposures 对齐：该暴露的事实来源是否可信
		add := func(kind, subject, priv string, evidence []string, scope string, viaRole string, src string) {
			ex := SensitiveExposure{
				LabelID: l.ID, Object: display, Kind: kind, Subject: subject,
				Privilege: priv, Evidence: evidence, Risk: "high",
			}
			if viaRole != "" {
				ex.Subject = subject + "（经角色 " + viaRole + "）"
				ex.Exempt = exempt(viaRole, priv, scope) || exempt(subject, priv, scope)
			} else {
				ex.Exempt = exempt(subject, priv, scope)
			}
			if ex.Exempt {
				ex.Note = "已基线放行（合法豁免），不计入违规暴露。"
			}
			labelExposures = append(labelExposures, ex)
			labelCredible = append(labelCredible, sensitiveSourceCredible(b, src))
		}
		// mysqlCaseIndeterminate 本标签是否存在模式未知且仅大小写不同的库级授权
		// （无法确认是否匹配，不计命中、不判不匹配）。
		mysqlCaseIndeterminate := false
		switch adapter {
		case facts.TargetDBOracle:
			// 容器归属：标签库名（PDB）须与本包可信容器身份对应——只认新采集器
			// 的 ora.container 事实（服务端 CON_NAME）加可信收据；Scope.Container
			// 不再作为依据（旧包中它是连接服务名，服务名与 PDB 名可能不同）。
			// 容器身份缺失、不符或收据不可信时不作跨容器匹配，整标签未确认
			// （同名表在不同 PDB 是不同对象；Scope.Instance 为写死占位值，不可信）。
			containerMismatch := false
			if l.Database != "" {
				if ok, reason := sensitiveOracleContainer(b, l.Database); !ok {
					containerMismatch = true
					snap.Notes = append(snap.Notes, reason)
				}
			}
			if containerMismatch {
				snap.Status = "unconfirmed"
				break
			}
			// PUBLIC 对象授权：Scope 为 OWNER.TABLE 精确匹配。
			for _, f := range oraTab {
				if !strings.EqualFold(f.Subject, "PUBLIC") {
					continue
				}
				owner, tbl, ok := splitOraScope(f.Scope)
				if !ok || !matchName(adapter, owner, l.Schema) || !matchName(adapter, tbl, l.Table) {
					continue
				}
				add("public", "PUBLIC", f.Attributes["privilege"], []string{f.FactID}, f.Scope, "", "ora.tab_privs")
			}
			// ANY 表权限：SYS 模式排除（字典保护）；DBA 角色按 M35 豁免
			// （固有管理权限，不报警）；角色传递只计默认激活角色。
			if !strings.EqualFold(l.Schema, "SYS") {
				for _, f := range oraSys {
					priv := f.Attributes["privilege"]
					if !isTableANY(priv) || strings.EqualFold(f.Subject, "DBA") {
						continue
					}
					// CDB 通用权限（common=YES，CONTAINER=ALL）可达全部 PDB，
					// 本节只计本包（本资产容器），跨 PDB 可达另行注记。
					common := f.Attributes["common"] == "YES"
					credUsers, uncredUsers, isRole, unknown := roles.expandGrantee(adapter, f.Subject)
					for _, u := range credUsers {
						via := ""
						if isRole {
							via = f.Subject
						}
						add("any", u, priv, []string{f.FactID}, f.Scope, via, f.Source)
						if common {
							labelExposures[len(labelExposures)-1].Note = "CONTAINER=ALL：该权限可达全部 PDB，本节只计本包。"
						}
					}
					if unknown && !exempt(f.Subject, priv, f.Scope) {
						// 身份未知：不得当成确定用户；显示疑似，不计确定暴露。
						add("any", f.Subject, priv, []string{f.FactID}, f.Scope, "", f.Source)
						labelCredible[len(labelCredible)-1] = false
						labelExposures[len(labelExposures)-1].Note = "被授者身份无法确认（角色边缺失/被拒且无可信用户清单），不能直接当成确定用户；不计入确定暴露。"
						snap.Notes = append(snap.Notes, "被授者 "+f.Subject+" 身份无法确认（非确认角色、非确认用户），不计入确定暴露。")
					}
					if isRole && len(uncredUsers) > 0 && !exempt(f.Subject, priv, f.Scope) {
						// 角色授权存在，但成员边来源不可信：只显角色授权，
						// 不计确定暴露（实际用户可达性未确认）。
						add("any", f.Subject, priv, []string{f.FactID}, f.Scope, "", f.Source)
						labelCredible[len(labelCredible)-1] = false
						labelExposures[len(labelExposures)-1].Note = "角色授权存在，但角色成员边来源不可信（被拒/失败/缺收据），无法确认实际用户可达性；不计入确定暴露。"
						snap.Notes = append(snap.Notes, "角色 "+f.Subject+" 的 "+priv+" 授权存在，但角色成员边来源不可信，无法确认实际用户可达性（不计入确定暴露）。")
					}
				}
			}
		case facts.TargetDBPostgres:
			for _, f := range pgObj {
				if !strings.EqualFold(f.Subject, "PUBLIC") {
					continue
				}
				if l.Database != "" && !matchName(adapter, f.Attributes["database"], l.Database) {
					continue
				}
				if !matchName(adapter, f.Attributes["schema"], l.Schema) ||
					!matchName(adapter, f.Attributes["object"], l.Table) {
					continue
				}
				add("public", "PUBLIC", f.Attributes["privilege"], []string{f.FactID}, f.Scope, "", "pg.object_privileges")
			}
			snap.Notes = append(snap.Notes,
				"PG 超级用户不受 ACL 限制，其可达性不在授权事实中体现，需另行核查超级用户清单。")
		case facts.TargetDBMySQL:
			// MySQL 无 PUBLIC：全局（*.*）与库级（db.*）数据权限即 broad 授权。
			// MySQL 的模式即库：标签库名优先，库名为空时用模式名匹配。
			effDB := l.Database
			if effDB == "" {
				effDB = l.Schema
			}
			for _, f := range myPriv {
				priv := f.Attributes["privilege"]
				if !dataPrivileges[priv] {
					continue
				}
				var kind string
				switch {
				case f.Scope == "*.*":
					kind = "global"
				case strings.HasSuffix(f.Scope, ".*"):
					dbName := strings.TrimSuffix(f.Scope, ".*")
					if matchMySQLDB(dbName, effDB) {
						kind = "database-wide"
					} else if !mysqlCaseKnown && strings.EqualFold(dbName, effDB) {
						// 模式未知且仅大小写不同：无法确认是否匹配，
						// 不计命中，也不判不匹配（标签置未确认）。
						mysqlCaseIndeterminate = true
						continue
					} else {
						continue
					}
				default:
					continue
				}
				credUsers, uncredUsers, isRole, unknown := roles.expandGrantee(adapter, f.Subject)
				for _, u := range credUsers {
					via := ""
					if isRole {
						via = f.Subject
					}
					add(kind, u, priv, []string{f.FactID}, f.Scope, via, f.Source)
				}
				if unknown && !exempt(f.Subject, priv, f.Scope) {
					// 身份未知：不得当成确定用户；显示疑似，不计确定暴露。
					add(kind, f.Subject, priv, []string{f.FactID}, f.Scope, "", f.Source)
					labelCredible[len(labelCredible)-1] = false
					labelExposures[len(labelExposures)-1].Note = "被授者身份无法确认（角色边缺失/被拒且无可信用户清单），不能直接当成确定用户；不计入确定暴露。"
					snap.Notes = append(snap.Notes, "被授者 "+f.Subject+" 身份无法确认（非确认角色、非确认用户），不计入确定暴露。")
				}
				if isRole && len(uncredUsers) > 0 && !exempt(f.Subject, priv, f.Scope) {
					// 角色授权存在，但成员边来源不可信：只显角色授权，
					// 不计确定暴露（实际用户可达性未确认）。
					add(kind, f.Subject, priv, []string{f.FactID}, f.Scope, "", f.Source)
					labelCredible[len(labelCredible)-1] = false
					labelExposures[len(labelExposures)-1].Note = "角色授权存在，但角色成员边来源不可信（被拒/失败/缺收据），无法确认实际用户可达性；不计入确定暴露。"
					snap.Notes = append(snap.Notes, "角色 "+f.Subject+" 的 "+priv+" 授权存在，但角色成员边来源不可信，无法确认实际用户可达性（不计入确定暴露）。")
				}
			}
		case facts.TargetDBSQLSrv:
			// MSSQL 事实只到数据库级（对象未采集）：无论有无数据库级 public 授权，
			// 都无法确认该表是否被 public 授权——恒为未确认，不计暴露、不判“未发现”。
			snap.Status = "unconfirmed"
			found := false
			for _, f := range mssqlPerm {
				if !strings.EqualFold(f.Subject, "public") {
					continue
				}
				dbName := strings.TrimPrefix(f.Scope, "database:")
				if l.Database != "" && !matchName(adapter, dbName, l.Database) {
					continue
				}
				snap.Notes = append(snap.Notes,
					"数据库级 public 授权存在（"+f.Attributes["permission"]+"），但对象级事实未采集，无法确认是否覆盖该表。")
				found = true
				break
			}
			if !found {
				snap.Notes = append(snap.Notes,
					"对象级授权事实未采集（MSSQL 采集只到数据库级），无法确认该表是否被 broad 授权。")
			}
		default:
			snap.Status = "unconfirmed"
			snap.Notes = append(snap.Notes, "该资产类型暂无 broad 授权匹配口径，无法判定。")
		}
		// 确定暴露只计来源可信的命中：partial 加可信命中可以报告；
		// 来源被拒/失败/缺收据的事实不作确定证据（不计暴露，标签未确认）。
		var definiteExposures []SensitiveExposure
		droppedViolations := 0
		for i, e := range labelExposures {
			if labelCredible[i] {
				definiteExposures = append(definiteExposures, e)
			} else if !e.Exempt {
				droppedViolations++
			}
		}
		violations := 0
		for _, e := range definiteExposures {
			if !e.Exempt {
				violations++
			}
		}
		if violations > 0 {
			// 已有可靠暴露证据：即使其他来源不完整，风险仍可报告。
			snap.Status = "exposed"
		} else if snap.Status != "unconfirmed" {
			if droppedViolations > 0 {
				// 有疑似命中但无可信来源：不能把不可信事实当确定证据。
				snap.Status = "unconfirmed"
				snap.Notes = append(snap.Notes, fmt.Sprintf("有 %d 条疑似 broad 授权事实，但其来源收据不可信（被拒/失败/缺失），不能作为确定暴露证据；请重采后复评。", droppedViolations))
			} else if mysqlCaseIndeterminate {
				// MySQL 模式未知且仅大小写不同的库级授权：无法确认是否匹配，
				// 不判“未发现”。
				snap.Status = "unconfirmed"
				snap.Notes = append(snap.Notes, "库名大小写模式未知（lower_case_table_names 未采集或无可信收据），且存在仅大小写不同的库级授权，无法确认是否覆盖该库；不判“未发现”。")
			} else if ok, incomplete := sensitiveSourcesComplete(b, adapter); !ok {
				// 无违规暴露时，只有相关来源全部完整检查且无命中，才可称“未发现”；
				// 来源缺失、失败或截断 → 未确认（Web 不显绿色），缺事实不等于安全。
				snap.Status = "unconfirmed"
				snap.Notes = append(snap.Notes, "相关授权来源采集不完整（"+strings.Join(incomplete, "、")+"），无法确认无 broad 授权；缺授权事实不等于安全。")
			} else {
				snap.Status = "no-broad-grant"
				if len(definiteExposures) > 0 {
					snap.Notes = append(snap.Notes, "匹配到的 broad 授权均已基线放行，不计入违规暴露。")
				}
			}
		}
		sec.Labels = append(sec.Labels, snap)
		sec.Exposures = append(sec.Exposures, definiteExposures...)
	}
	if len(labels) == 0 {
		sec.Notes = append(sec.Notes, "本对象未标记敏感对象；未标记不等于不敏感。")
	}
	return sec
}

// splitOraScope 拆 Oracle 对象 Scope（OWNER.TABLE）；无点号时不匹配。
func splitOraScope(scope string) (owner, table string, ok bool) {
	i := strings.Index(scope, ".")
	if i <= 0 || i == len(scope)-1 {
		return "", "", false
	}
	return scope[:i], scope[i+1:], true
}

// BuildSensitiveSection 报告生成时调用：取该资产当前标签（快照），
// 匹配包事实，基线按医院全部基线合并（与 M35 自动屏蔽同口径）。
// 非数据库资产不建节；标签读取失败时返回 nil（报告其余部分不受影响）；
// 基线加载失败时豁免未标记并注记。
func BuildSensitiveSection(db *sql.DB, hospitalID, assetID string, b *facts.FactBundle) *SensitiveSection {
	if b == nil {
		return nil
	}
	switch b.Collector.Adapter {
	case facts.TargetDBOracle, facts.TargetDBMySQL, facts.TargetDBPostgres, facts.TargetDBSQLSrv:
	default:
		return nil
	}
	labels, err := ListSensitiveLabels(db, hospitalID, assetID)
	if err != nil {
		return nil
	}
	var baseline *rules.Baseline
	if b != nil {
		if bl, _, err := LoadHospitalBaselines(db, hospitalID, string(b.Collector.Adapter)); err == nil {
			baseline = bl
		}
	}
	sec := MatchSensitive(b, labels, baseline)
	if baseline == nil {
		sec.Notes = append(sec.Notes, "基线加载失败，豁免未标记；请核对基线页。")
	}
	return sec
}
