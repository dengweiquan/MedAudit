package main

// 与服务端 API 对齐的响应结构（字段以 web/src/api.ts 与实测响应为准）。

type evalSummary struct {
	BundleID       string `json:"bundle_id"`
	Total          int    `json:"total"`
	Pass           int    `json:"pass"`
	Fail           int    `json:"fail"`
	Unknown        int    `json:"unknown"`
	NotApplicable  int    `json:"not_applicable"`
	NotRun         int    `json:"not_run"`
	FindingsStored int    `json:"findings_stored"`
}

type auditRunResult struct {
	BundleID           string      `json:"bundle_id"`
	Facts              int         `json:"facts"`
	Receipts           int         `json:"receipts"`
	Evaluation         evalSummary `json:"evaluation"`
	ReportID           string      `json:"report_id"`
	Transport          string      `json:"transport,omitempty"`
	HostKeyFingerprint string      `json:"host_key_fingerprint,omitempty"`
}

type bundleSummary struct {
	ID           string `json:"id"`
	PlanID       string `json:"plan_id"`
	HospitalID   string `json:"hospital_id"`
	AssetID      string `json:"asset_id"`
	Adapter      string `json:"adapter"`
	Execution    string `json:"execution"`
	FactCount    int    `json:"fact_count"`
	ReceiptCount int    `json:"receipt_count"`
	ImportedAt   string `json:"imported_at"`
}

type findingRow struct {
	ID           int    `json:"id"`
	BundleID     string `json:"bundle_id"`
	RuleID       string `json:"rule_id"`
	RuleVersion  string `json:"rule_version"`
	Subject      string `json:"subject"`
	Conclusion   string `json:"conclusion"`
	Detail       string `json:"detail"`
	ReviewStatus string `json:"review_status"`
	CreatedAt    string `json:"created_at"`
}

func (f findingRow) detailText() string {
	var d struct {
		Detail string `json:"detail"`
	}
	if err := jsonUnmarshal([]byte(f.Detail), &d); err == nil && d.Detail != "" {
		return d.Detail
	}
	return f.Detail
}

type reportRow struct {
	ID         string `json:"id"`
	HospitalID string `json:"hospital_id"`
	PlanID     string `json:"plan_id"`
	BundleID   string `json:"bundle_id"`
	CreatedBy  string `json:"created_by"`
	CreatedAt  string `json:"created_at"`
}

type hospitalSummary struct {
	HospitalID   string `json:"hospital_id"`
	Assets       int    `json:"assets"`
	Bundles      int    `json:"bundles"`
	FailTotal    int    `json:"fail_total"`
	FailOpen     int    `json:"fail_open"`
	UnknownTotal int    `json:"unknown_total"`
	CorrPaths    int    `json:"corr_paths"`
	LastBundleAt string `json:"last_bundle_at"`
}

type assetRow struct {
	ID         string  `json:"id"`
	HospitalID string  `json:"hospital_id"`
	Kind       string  `json:"kind"`
	Name       string  `json:"name"`
	Endpoint   *string `json:"endpoint"`
	Labels     *string `json:"labels"`
}

type bundleDetail struct {
	ID               string         `json:"id"`
	HospitalID       string         `json:"hospital_id"`
	PlanID           string         `json:"plan_id"`
	AssetID          string         `json:"asset_id"`
	Adapter          string         `json:"adapter"`
	Execution        string         `json:"execution"`
	ImportedAt       string         `json:"imported_at"`
	CollectorVersion string         `json:"collector_version"`
	FactCount        int            `json:"fact_count"`
	CountsByKind     map[string]int `json:"counts_by_kind"`
	Receipts         []struct {
		TemplateID string `json:"template_id"`
		Status     string `json:"status"`
		RowCount   int    `json:"row_count"`
		Truncated  bool   `json:"truncated"`
		ErrorStage string `json:"error_stage"`
	} `json:"receipts"`
}

type baselineAllow struct {
	Subject string `json:"Subject"`
	Kind    string `json:"Kind"`
	Value   string `json:"Value"`
	Scope   string `json:"Scope"`
	Reason  string `json:"Reason"`
}

type baselineRow struct {
	ID         string `json:"id"`
	HospitalID string `json:"hospital_id"`
	Target     string `json:"target"`
	Version    int    `json:"version"`
	Spec       string `json:"spec"`
}

type baselineFile struct {
	ID         string          `json:"id"`
	HospitalID string          `json:"hospital_id"`
	Target     string          `json:"target"`
	Allows     []baselineAllow `json:"allows"`
	CreatedBy  string          `json:"created_by,omitempty"`
}

type ruleSpecRow struct {
	ID      string `json:"ID"`
	Name    string `json:"Name"`
	Target  string `json:"Target"`
	Risk    string `json:"Risk"`
	Version string `json:"Version"`
}

type ruleToggleRow struct {
	RuleID    string `json:"rule_id"`
	Enabled   bool   `json:"enabled"`
	Reason    string `json:"reason"`
	UpdatedBy string `json:"updated_by"`
	UpdatedAt string `json:"updated_at"`
}

type userRow struct {
	Username      string `json:"username"`
	Disabled      bool   `json:"disabled"`
	MustChangePwd bool   `json:"must_change_pwd"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

type remScript struct {
	RuleID   string `json:"rule_id"`
	Subject  string `json:"subject"`
	Scope    string `json:"scope,omitempty"`
	Precheck string `json:"precheck"`
	Fix      string `json:"fix"`
	Verify   string `json:"verify"`
	Rollback string `json:"rollback"`
	Note     string `json:"note,omitempty"`
}

type reportDetail struct {
	HospitalID  string `json:"hospital_id"`
	PlanID      string `json:"plan_id"`
	BundleID    string `json:"bundle_id"`
	GeneratedAt string `json:"generated_at"`
	Findings    []struct {
		RuleID     string `json:"rule_id"`
		Conclusion string `json:"conclusion"`
	} `json:"findings"`
	Remediation *struct {
		FailTotal int         `json:"fail_total"`
		Generated int         `json:"generated"`
		Scripts   []remScript `json:"scripts"`
	} `json:"remediation"`
	PrivilegePaths []struct{} `json:"privilege_paths"`
	Drift          any        `json:"drift"`
}
