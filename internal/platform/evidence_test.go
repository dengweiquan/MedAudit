package platform

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEvidenceRoundtrip(t *testing.T) {
	kr, err := NewEvidenceKeyring(2, map[uint16][]byte{1: testKey(t), 2: testKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("fake zip bytes for roundtrip")
	blob, err := kr.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, plain) {
		t.Fatal("密文不应包含明文")
	}
	got, err := kr.Decrypt(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("解密结果与明文不一致")
	}
}

func TestEvidenceOldVersionStillDecrypts(t *testing.T) {
	k1 := testKey(t)
	old, err := NewEvidenceKeyring(1, map[uint16][]byte{1: k1})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := old.Encrypt([]byte("v1 evidence"))
	if err != nil {
		t.Fatal(err)
	}
	// 轮换到 v2 后，带 v1 历史密钥的密钥环仍可解 v1 证据。
	rotated, err := NewEvidenceKeyring(2, map[uint16][]byte{1: k1, 2: testKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := rotated.Decrypt(blob)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v1 evidence" {
		t.Fatalf("历史版本解密错误: %q", got)
	}
	// 缺 v1 密钥时必须明确报错，而不是静默返回乱码。
	only2, err := NewEvidenceKeyring(2, map[uint16][]byte{2: testKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := only2.Decrypt(blob); !errors.Is(err, ErrEvidenceKeyMissing) {
		t.Fatalf("缺历史密钥应报 ErrEvidenceKeyMissing, got %v", err)
	}
}

func TestEvidenceTamperDetected(t *testing.T) {
	kr, err := NewEvidenceKeyring(1, map[uint16][]byte{1: testKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := kr.Encrypt([]byte("integrity matters"))
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 0xFF
	if _, err := kr.Decrypt(blob); err == nil {
		t.Fatal("篡改密文必须解密失败（GCM 认证）")
	}
}

func TestEvidencePlaintextCompat(t *testing.T) {
	kr, err := NewEvidenceKeyring(1, map[uint16][]byte{1: testKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("legacy plaintext blob")
	got, err := kr.Decrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("无 MAE1 头的 blob 应按明文兼容返回")
	}
}

func TestEvidenceKeyringFromEnv(t *testing.T) {
	k := base64.StdEncoding.EncodeToString(testKey(t))
	env := map[string]string{"MEDAUDIT_EVIDENCE_KEY": k, "MEDAUDIT_EVIDENCE_KEY_VERSION": "3"}
	kr, err := loadEvidenceKeyring(func(s string) string { return env[s] })
	if err != nil {
		t.Fatal(err)
	}
	if kr == nil || kr.CurrentVersion() != 3 {
		t.Fatalf("env 装配错误: %+v", kr)
	}
	kr2, err := loadEvidenceKeyring(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if kr2 != nil {
		t.Fatal("未配置密钥时应返回 nil（证据加密禁用）")
	}
}
