package linux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseOratab(t *testing.T) {
	raw := "# comment\n\norcl:/u01/app/oracle/product/19c/dbhome_1:N\n" +
		"  zemr:/u01/app/oracle/product/11g/dbhome_1:Y\n" +
		"badline\n" +
		":/no/sid:N\n"
	entries := ParseOratab([]byte(raw))
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d: %+v", len(entries), entries)
	}
	if entries[0].SID != "orcl" || entries[1].Home != "/u01/app/oracle/product/11g/dbhome_1" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestParseSqlnetOra(t *testing.T) {
	raw := "# comment\n" +
		"SQLNET.ENCRYPTION_SERVER = accepted\n" +
		"sqlnet.encryption_types_server = (AES256, AES192)\n" +
		"SQLNET.ENCRYPTION_SERVER = required\n" +
		"IFILE = /etc/oracle/common.ora\n" +
		"badline\n"
	params, ifiles := ParseSqlnetOra([]byte(raw))
	// 后出现覆盖先前；键大小写不敏感。
	if params["SQLNET.ENCRYPTION_SERVER"] != "required" {
		t.Fatalf("want required, got %q", params["SQLNET.ENCRYPTION_SERVER"])
	}
	if params["SQLNET.ENCRYPTION_TYPES_SERVER"] != "(AES256, AES192)" {
		t.Fatalf("unexpected types: %q", params["SQLNET.ENCRYPTION_TYPES_SERVER"])
	}
	if len(ifiles) != 1 || ifiles[0] != "/etc/oracle/common.ora" {
		t.Fatalf("unexpected ifiles: %v", ifiles)
	}
}

func TestResolveSqlnetOra(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sqlnet.ora")
	sub := filepath.Join(dir, "common.ora")
	os.WriteFile(main, []byte("SQLNET.ENCRYPTION_SERVER = accepted\nIFILE = common.ora\n"), 0644)
	os.WriteFile(sub, []byte("SQLNET.ENCRYPTION_SERVER = required\nSQLNET.ENCRYPTION_TYPES_SERVER = (AES256)\n"), 0644)
	params, chain, err := ResolveSqlnetOra(os.ReadFile, main)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// IFILE 后出现覆盖主文件。
	if params["SQLNET.ENCRYPTION_SERVER"] != "required" {
		t.Fatalf("want required, got %q", params["SQLNET.ENCRYPTION_SERVER"])
	}
	if len(chain) != 2 || chain[0] != main || chain[1] != sub {
		t.Fatalf("unexpected chain: %v", chain)
	}
}

func TestResolveSqlnetOraCycle(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.ora")
	b := filepath.Join(dir, "b.ora")
	os.WriteFile(a, []byte("IFILE = b.ora\n"), 0644)
	os.WriteFile(b, []byte("IFILE = a.ora\n"), 0644)
	if _, _, err := ResolveSqlnetOra(os.ReadFile, a); err == nil {
		t.Fatal("want cycle error, got nil")
	} else if !strings.Contains(err.Error(), "环") {
		t.Fatalf("want cycle error, got %v", err)
	}
}

func TestResolveSqlnetOraDepth(t *testing.T) {
	dir := t.TempDir()
	prev := ""
	for i := 0; i <= SqlnetMaxIFILEDepth+1; i++ {
		p := filepath.Join(dir, "f"+itoa(i)+".ora")
		if prev != "" {
			os.WriteFile(prev, []byte("IFILE = "+filepath.Base(p)+"\n"), 0644)
		}
		prev = p
	}
	os.WriteFile(prev, []byte("SQLNET.ENCRYPTION_SERVER = required\n"), 0644)
	if _, _, err := ResolveSqlnetOra(os.ReadFile, filepath.Join(dir, "f0.ora")); err == nil {
		t.Fatal("want depth error, got nil")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestLocateSqlnetOra(t *testing.T) {
	if got := LocateSqlnetOra("/u01/dbhome", ""); got != "/u01/dbhome/network/admin/sqlnet.ora" {
		t.Fatalf("default: %s", got)
	}
	if got := LocateSqlnetOra("/u01/dbhome", "/opt/tns"); got != "/opt/tns/sqlnet.ora" {
		t.Fatalf("tns-admin: %s", got)
	}
}
