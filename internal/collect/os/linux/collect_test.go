package linux

import (
	"context"
	"testing"
	"time"

	"medaudit/internal/facts"
)

// TestCollectLive 在本机（kf7，root）真实采集 cron.service。
func TestCollectLive(t *testing.T) {
	if _, err := ReadUnit(context.Background(), "cron.service"); err != nil {
		t.Skipf("cron.service 不可用：%v", err)
	}
	cfg := Config{
		HospitalID: "h-m1-test", AssetID: "host-kf7", PlanID: "plan-m1-os",
		Services:         []string{"cron.service"},
		CollectorVersion: "0.1.0-m1",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := Collect(ctx, cfg)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if errs := b.Validate(); len(errs) != 0 {
		t.Fatalf("bundle validate: %v", errs)
	}
	if b.Execution != facts.ExecutionComplete && b.Execution != facts.ExecutionPartial {
		t.Fatalf("execution = %s", b.Execution)
	}
	kinds := map[facts.FactKind]int{}
	for _, f := range b.Facts {
		kinds[f.Kind]++
	}
	t.Logf("facts=%d kinds=%v receipts=%d execution=%s",
		len(b.Facts), kinds, len(b.Receipts), b.Execution)
	if kinds[facts.FactProcess] == 0 {
		t.Error("没有采集到进程事实")
	}
	if kinds[facts.FactFilePerm] == 0 {
		t.Error("没有采集到文件权限事实")
	}
	// 进程键必须包含 boot_id 且采集前后已核对
	for _, f := range b.Facts {
		if f.Kind == facts.FactProcess && f.Status == facts.StatusInconsistent {
			t.Errorf("进程 %s 在采集期间发生变化（PID 复用）", f.Subject)
		}
	}
}

// TestProcKeyStable 进程键格式：node/boot_id/pid/starttime。
func TestProcKeyStable(t *testing.T) {
	p := &ProcInfo{PID: 1234, StartTime: 5678}
	k := ProcKey("n1", "boot-1", p)
	if k != "n1/boot-1/1234/5678" {
		t.Fatalf("proc key = %q", k)
	}
}

// TestDecodeCaps 能力位图解析。
func TestDecodeCaps(t *testing.T) {
	caps := DecodeCaps(0x1) // bit0 = CAP_CHOWN
	if len(caps) != 1 || caps[0] != "CAP_CHOWN" {
		t.Fatalf("caps = %v", caps)
	}
	if !IsFullRoot(0x1ffffffffff) {
		t.Fatal("全能力集应判定为 full root")
	}
	if IsFullRoot(0x0) {
		t.Fatal("空能力集不应判定为 full root")
	}
}
