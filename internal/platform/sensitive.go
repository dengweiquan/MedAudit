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

// roleResolution 从角色边事实建解析表：roles 为全部角色名（边
// PermissionPath[0]），defaultUsers 为角色 → 默认激活用户。
// 角色与用户共用命名空间：出现在边中的名字即角色；角色权限只通过
// 默认激活边到达用户，非默认角色需 SET ROLE 激活，不计入自动可达。
type roleResolution struct {
	roles        map[string]bool
	defaultUsers map[string][]string
}

func resolveRoles(b *facts.FactBundle) roleResolution {
	r := roleResolution{roles: map[string]bool{}, defaultUsers: map[string][]string{}}
	for _, f := range b.Facts {
		if f.Kind != facts.FactRoleEdge || len(f.PermissionPath) == 0 {
			continue
		}
		role := f.PermissionPath[0]
		r.roles[role] = true
		if f.Activation == facts.ActivationDefault {
			r.defaultUsers[role] = append(r.defaultUsers[role], f.Subject)
		}
	}
	return r
}

// grantees 把被授者解析为实际用户：角色只展开默认激活用户（无默认用户时
// 返回空，即不计暴露）；非角色名即用户本人。
func (r roleResolution) grantees(subject string) ([]string, bool) {
	if !r.roles[subject] {
		return []string{subject}, false
	}
	return r.defaultUsers[subject], true
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
		add := func(kind, subject, priv string, evidence []string, scope string, viaRole string) {
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
		}
		switch adapter {
		case facts.TargetDBOracle:
			// PUBLIC 对象授权：Scope 为 OWNER.TABLE 精确匹配。
			for _, f := range oraTab {
				if !strings.EqualFold(f.Subject, "PUBLIC") {
					continue
				}
				owner, tbl, ok := splitOraScope(f.Scope)
				if !ok || !matchName(adapter, owner, l.Schema) || !matchName(adapter, tbl, l.Table) {
					continue
				}
				if l.Database != "" {
					// Oracle 事实不带 PDB 名：标签库名无法与事实库名对应，
					// 以资产（包）为界，不再按库名过滤（见文档注记）。
					_ = l.Database
				}
				add("public", "PUBLIC", f.Attributes["privilege"], []string{f.FactID}, f.Scope, "")
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
					users, isRole := roles.grantees(f.Subject)
					for _, u := range users {
						via := ""
						if isRole {
							via = f.Subject
						}
						add("any", u, priv, []string{f.FactID}, f.Scope, via)
						if common {
							labelExposures[len(labelExposures)-1].Note = "CONTAINER=ALL：该权限可达全部 PDB，本节只计本包。"
						}
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
				add("public", "PUBLIC", f.Attributes["privilege"], []string{f.FactID}, f.Scope, "")
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
				case strings.HasSuffix(f.Scope, ".*") &&
					matchName(adapter, strings.TrimSuffix(f.Scope, ".*"), effDB):
					kind = "database-wide"
				default:
					continue
				}
				users, isRole := roles.grantees(f.Subject)
				for _, u := range users {
					via := ""
					if isRole {
						via = f.Subject
					}
					add(kind, u, priv, []string{f.FactID}, f.Scope, via)
				}
			}
		case facts.TargetDBSQLSrv:
			// MSSQL 事实只到数据库级（对象未采集）：public 授权存在时无法确认
			// 是否覆盖该表——列为未确认，不计暴露、不判安全。
			for _, f := range mssqlPerm {
				if !strings.EqualFold(f.Subject, "public") {
					continue
				}
				dbName := strings.TrimPrefix(f.Scope, "database:")
				if l.Database != "" && !matchName(adapter, dbName, l.Database) {
					continue
				}
				snap.Status = "unconfirmed"
				snap.Notes = append(snap.Notes,
					"数据库级 public 授权存在（"+f.Attributes["permission"]+"），但对象级事实未采集，无法确认是否覆盖该表。")
				break
			}
		default:
			snap.Status = "unconfirmed"
			snap.Notes = append(snap.Notes, "该资产类型暂无 broad 授权匹配口径，无法判定。")
		}
		violations := 0
		for _, e := range labelExposures {
			if !e.Exempt {
				violations++
			}
		}
		if violations > 0 {
			snap.Status = "exposed"
		} else if snap.Status != "unconfirmed" {
			snap.Status = "no-broad-grant"
			if len(labelExposures) > 0 {
				snap.Notes = append(snap.Notes, "匹配到的 broad 授权均已基线放行，不计入违规暴露。")
			}
		}
		sec.Labels = append(sec.Labels, snap)
		sec.Exposures = append(sec.Exposures, labelExposures...)
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
