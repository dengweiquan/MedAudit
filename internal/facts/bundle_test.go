package facts

import (
	"encoding/json"
	"testing"
	"time"
)

func sampleBundle() *FactBundle {
	now := time.Now().UTC().Truncate(time.Second)
	return &FactBundle{
		SchemaVersion: SchemaVersion,
		BundleID:      "bundle-test-001",
		PlanID:        "plan-test-001",
		Collector: CollectorInfo{
			Name:           "medaudit-collector",
			Version:        "0.1.0-m0",
			Adapter:        TargetDBMySQL,
			AdapterVersion: "0.1.0",
		},
		CollectedAt: TimeRange{Started: now, Finished: now},
		Scope: Scope{
			HospitalID: "h-test",
			AssetID:    "db-mysql-01",
			TargetType: TargetDBMySQL,
		},
		Identities: Identities{
			CollectorIdentity: "medaudit_ro@collector",
			TargetIdentity:    "app_svc@10.0.0.5",
			AppIdentitySource: "config",
		},
		Facts: []Fact{
			{
				FactID:     "fact-001",
				Kind:       FactPrivilege,
				Subject:    "app_svc@10.0.0.5",
				Status:     StatusObserved,
				Source:     "mysql.user",
				Attributes: map[string]string{"priv": "SELECT", "scope": "db:his"},
				Activation: ActivationDefault,
			},
			{
				FactID:  "fact-002",
				Kind:    FactRoleEdge,
				Subject: "app_svc@10.0.0.5",
				Status:  StatusPermissionDenied,
				Source:  "mysql.role_edges",
			},
		},
		Receipts: []Receipt{
			{
				TemplateID:      "mysql.user_privs",
				TemplateVersion: "1",
				Started:         now,
				Finished:        now,
				RowCount:        1,
				Status:          "ok",
			},
		},
		Execution: ExecutionComplete,
	}
}

func TestValidateOK(t *testing.T) {
	b := sampleBundle()
	if errs := b.Validate(); len(errs) != 0 {
		t.Fatalf("unexpected validation errors: %v", errs)
	}
}

func TestValidateRejectsMergedIdentity(t *testing.T) {
	b := sampleBundle()
	b.Identities.TargetIdentity = b.Identities.CollectorIdentity
	if errs := b.Validate(); len(errs) == 0 {
		t.Fatal("expected validation error for merged identities")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	b := sampleBundle()
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema_version", "bundle_id", "plan_id", "collector", "collected_at", "scope", "identities", "facts", "receipts"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing required key %q in marshaled JSON", k)
		}
	}
	var back FactBundle
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Facts[1].Status != StatusPermissionDenied {
		t.Fatal("field status permission_denied did not survive round trip")
	}
}
