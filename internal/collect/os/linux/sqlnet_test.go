package linux

import (
	"os"
	"path/filepath"
	"testing"

	"medaudit/internal/facts"
)

func TestCollectOracleSqlnet(t *testing.T) {
	etc := t.TempDir()
	homeReq := filepath.Join(etc, "home-req")
	homeAcc := filepath.Join(etc, "home-acc")
	homeMissing := filepath.Join(etc, "home-missing")
	for _, h := range []string{homeReq, homeAcc} {
		os.MkdirAll(filepath.Join(h, "network", "admin"), 0755)
	}
	os.WriteFile(filepath.Join(homeReq, "network", "admin", "sqlnet.ora"),
		[]byte("SQLNET.ENCRYPTION_SERVER = required\n"), 0644)
	os.WriteFile(filepath.Join(homeAcc, "network", "admin", "sqlnet.ora"),
		[]byte("# no encryption param\nNAMES.DIRECTORY_PATH = (TNSNAMES)\n"), 0644)
	os.WriteFile(filepath.Join(etc, "oratab"),
		[]byte("ORCL:"+homeReq+":N\nACC:"+homeAcc+":N\nMIS:"+homeMissing+":N\n"), 0644)

	b := &facts.FactBundle{}
	execStatus := facts.ExecutionComplete
	var receipts []facts.Receipt
	collectOracleSqlnet(b, etc, func(r facts.Receipt) { receipts = append(receipts, r) }, &execStatus)
	if len(receipts) != 1 || receipts[0].Status != "ok" {
		t.Fatalf("receipt: %+v", receipts)
	}
	if execStatus != facts.ExecutionComplete {
		t.Fatalf("execStatus: %v", execStatus)
	}
	byHome := map[string]map[string]string{}
	for _, f := range b.Facts {
		if f.Source == "linux.oracle_sqlnet" {
			byHome[f.Attributes["oracle_home"]] = f.Attributes
		}
	}
	if byHome[homeReq]["encryption_server"] != "required" {
		t.Fatalf("req home: %+v", byHome[homeReq])
	}
	// 参数缺失取缺省 accepted。
	if byHome[homeAcc]["encryption_server"] != "accepted" || byHome[homeAcc]["param_missing"] != "true" {
		t.Fatalf("acc home: %+v", byHome[homeAcc])
	}
	// 文件缺失取缺省 accepted。
	if byHome[homeMissing]["encryption_server"] != "accepted" || byHome[homeMissing]["file_missing"] != "true" {
		t.Fatalf("missing home: %+v", byHome[homeMissing])
	}
}

func TestCollectOracleSqlnetNoOratab(t *testing.T) {
	etc := t.TempDir()
	b := &facts.FactBundle{}
	execStatus := facts.ExecutionComplete
	var receipts []facts.Receipt
	collectOracleSqlnet(b, etc, func(r facts.Receipt) { receipts = append(receipts, r) }, &execStatus)
	if len(receipts) != 1 || receipts[0].Status != "ok" {
		t.Fatalf("receipt: %+v", receipts)
	}
	found := false
	for _, f := range b.Facts {
		if f.Source == "linux.oracle_sqlnet" && f.Attributes["oracle_homes"] == "0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want inventory fact, got %+v", b.Facts)
	}
}
