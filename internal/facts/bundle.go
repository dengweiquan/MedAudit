// Package facts 定义 MedAudit v1 事实包契约的 Go 类型。
// 与 contracts/v1/factbundle.schema.json 保持一致；改动需双边同步。
package facts

import "time"

// SchemaVersion 当前契约版本。
const SchemaVersion = "v1"

// FieldStatus 字段采集状态。超时、截断、缺失、权限不足不得转为空权限或安全默认值。
type FieldStatus string

const (
	StatusObserved         FieldStatus = "observed"
	StatusPermissionDenied FieldStatus = "permission_denied"
	StatusUnsupported      FieldStatus = "unsupported"
	StatusInconsistent     FieldStatus = "inconsistent"
	StatusTruncated        FieldStatus = "truncated"
	StatusTimeout          FieldStatus = "timeout"
)

// Conclusion 技术结论（规则评估输出，与人工复核/整改状态分开）。
type Conclusion string

const (
	ConclusionPass          Conclusion = "PASS"
	ConclusionFail          Conclusion = "FAIL"
	ConclusionUnknown       Conclusion = "UNKNOWN"
	ConclusionNotRun        Conclusion = "NOT_RUN"
	ConclusionNotApplicable Conclusion = "NOT_APPLICABLE"
)

// ExecutionStatus 采集执行状态（完成取证不等于符合基线）。
type ExecutionStatus string

const (
	ExecutionComplete ExecutionStatus = "COMPLETE"
	ExecutionPartial  ExecutionStatus = "PARTIAL"
	ExecutionFailed   ExecutionStatus = "FAILED"
)

// TargetType 采集目标类型。
type TargetType string

const (
	TargetOSLinux    TargetType = "os-linux"
	TargetOSWindows  TargetType = "os-windows"
	TargetOSHpux     TargetType = "os-hpux" // M21
	TargetDBOracle   TargetType = "db-oracle"
	TargetDBSQLSrv   TargetType = "db-sqlserver"
	TargetDBMySQL    TargetType = "db-mysql"
	TargetDBPostgres TargetType = "db-postgres"
	TargetMWTomcat   TargetType = "mw-tomcat"
	TargetMWNginx    TargetType = "mw-nginx"
	TargetMWWebLogic TargetType = "mw-weblogic"
	TargetMWIIS      TargetType = "mw-iis"
)

// FactKind 事实种类。
type FactKind string

const (
	FactIdentity      FactKind = "identity"
	FactRoleEdge      FactKind = "role_edge"
	FactPrivilege     FactKind = "privilege"
	FactAccountConfig FactKind = "account_config"
	FactProcess       FactKind = "process"
	FactFilePerm      FactKind = "file_perm"
	FactServiceConfig FactKind = "service_config"
)

// Activation 权限激活条件。
type Activation string

const (
	ActivationDefault        Activation = "default"
	ActivationConditional    Activation = "conditional"
	ActivationObservedActive Activation = "observed_active"
	ActivationNotActivated   Activation = "not_activated"
	ActivationUnknown        Activation = "unknown"
)

// CollectorInfo 采集器与适配器版本信息。
type CollectorInfo struct {
	Name           string     `json:"name"`
	Version        string     `json:"version"`
	Adapter        TargetType `json:"adapter"`
	AdapterVersion string     `json:"adapter_version"`
}

// TimeRange 采集起止时间。
type TimeRange struct {
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
}

// Scope 采集范围。
type Scope struct {
	HospitalID    string     `json:"hospital_id"`
	AssetID       string     `json:"asset_id"`
	TargetType    TargetType `json:"target_type"`
	TargetVersion string     `json:"target_version,omitempty"`
	Instance      string     `json:"instance,omitempty"`
	Container     string     `json:"container,omitempty"`
	Profile       string     `json:"profile,omitempty"`
	Window        string     `json:"window,omitempty"`
}

// Identities 身份三元组：采集身份、被核查身份、应用关联来源必须分开。
type Identities struct {
	CollectorIdentity       string `json:"collector_identity"`
	TargetIdentity          string `json:"target_identity"`
	ObservedSessionIdentity string `json:"observed_session_identity,omitempty"`
	AppIdentitySource       string `json:"app_identity_source,omitempty"`
}

// Fact 单条事实。
type Fact struct {
	FactID         string            `json:"fact_id"`
	Kind           FactKind          `json:"kind"`
	Subject        string            `json:"subject"`
	Status         FieldStatus       `json:"status"`
	Source         string            `json:"source"`
	Attributes     map[string]string `json:"attributes,omitempty"`
	PermissionPath []string          `json:"permission_path,omitempty"`
	Scope          string            `json:"scope,omitempty"`
	Activation     Activation        `json:"activation,omitempty"`
	Grantable      *bool             `json:"grantable,omitempty"`
}

// Receipt 模板查询收据。
type Receipt struct {
	TemplateID      string    `json:"template_id"`
	TemplateVersion string    `json:"template_version"`
	ParamDigest     string    `json:"param_digest,omitempty"`
	Started         time.Time `json:"started"`
	Finished        time.Time `json:"finished"`
	DurationMs      int64     `json:"duration_ms"`
	RowCount        int       `json:"row_count"`
	Truncated       bool      `json:"truncated"`
	Status          string    `json:"status"`
	ErrorStage      string    `json:"error_stage,omitempty"`
	Visibility      string    `json:"visibility,omitempty"`
	EvidenceRef     string    `json:"evidence_ref,omitempty"`
}

// FactBundle v1 事实包。
type FactBundle struct {
	SchemaVersion  string          `json:"schema_version"`
	BundleID       string          `json:"bundle_id"`
	PlanID         string          `json:"plan_id"`
	Collector      CollectorInfo   `json:"collector"`
	CollectedAt    TimeRange       `json:"collected_at"`
	Scope          Scope           `json:"scope"`
	Identities     Identities      `json:"identities"`
	Facts          []Fact          `json:"facts"`
	Receipts       []Receipt       `json:"receipts"`
	Execution      ExecutionStatus `json:"execution,omitempty"`
	EvidenceDigest string          `json:"evidence_digest,omitempty"`
}

// Validate 做最基础的结构校验（JSON Schema 负责完整校验）。
func (b *FactBundle) Validate() []string {
	var errs []string
	if b.SchemaVersion != SchemaVersion {
		errs = append(errs, "schema_version must be v1")
	}
	if b.BundleID == "" {
		errs = append(errs, "bundle_id required")
	}
	if b.PlanID == "" {
		errs = append(errs, "plan_id required")
	}
	if b.Collector.Adapter == "" {
		errs = append(errs, "collector.adapter required")
	}
	if b.Identities.CollectorIdentity == "" || b.Identities.TargetIdentity == "" {
		errs = append(errs, "identities.collector_identity and target_identity required")
	}
	if b.Identities.CollectorIdentity == b.Identities.TargetIdentity {
		errs = append(errs, "collector and target identities must not be merged")
	}
	return errs
}
