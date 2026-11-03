package windows

import "testing"

func TestMSSQLSuperSocketPath(t *testing.T) {
	want := `SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQLServer\SuperSocketNetLib`
	if got := MSSQLSuperSocketPath("MSSQL13.MSSQLSERVER"); got != want {
		t.Fatalf("got %s", got)
	}
}

func TestMSSQLForceEncryptionAttrs(t *testing.T) {
	inst := MSSQLInstance{Name: "MSSQLSERVER", ID: "MSSQL13.MSSQLSERVER"}
	on := MSSQLForceEncryptionAttrs(inst, "p", true, true)
	if on["force_encryption"] != "1" || on["effective"] != "unknown" {
		t.Fatalf("on: %+v", on)
	}
	off := MSSQLForceEncryptionAttrs(inst, "p", true, false)
	if off["force_encryption"] != "0" || off["value_missing"] != "" {
		t.Fatalf("off: %+v", off)
	}
	// 值缺失取缺省 0 并标注。
	missing := MSSQLForceEncryptionAttrs(inst, "p", false, false)
	if missing["force_encryption"] != "0" || missing["value_missing"] != "true" {
		t.Fatalf("missing: %+v", missing)
	}
}
