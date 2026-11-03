package windows

import (
	"testing"
	"unicode/utf16"
)

func encodeUTF16LE(s string, bom bool) []byte {
	u16 := utf16.Encode([]rune(s))
	out := []byte{}
	if bom {
		out = append(out, 0xFF, 0xFE)
	}
	for _, u := range u16 {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

const seceditSample = "[Unicode]\nUnicode=yes\n[System Access]\n" +
	"MinimumPasswordLength = 7\nMaximumPasswordAge = 90\n" +
	"PasswordComplexity = 1\nLockoutBadCount = 5\n" +
	"; 注释行\n[Event Audit]\nAuditSystemEvents = 3\n"

func TestParseSeceditInfUTF16BOM(t *testing.T) {
	m := ParseSeceditInf(encodeUTF16LE(seceditSample, true))
	if m["passwordcomplexity"] != "1" {
		t.Fatalf("passwordcomplexity = %q, want 1", m["passwordcomplexity"])
	}
	if m["minimumpasswordlength"] != "7" {
		t.Fatalf("minimumpasswordlength = %q, want 7", m["minimumpasswordlength"])
	}
	if _, ok := m["auditsystemevents"]; ok {
		t.Fatalf("不应解析 [Event Audit] 段的键")
	}
}

func TestParseSeceditInfNoBOMAndASCII(t *testing.T) {
	m := ParseSeceditInf(encodeUTF16LE(seceditSample, false))
	if m["passwordcomplexity"] != "1" {
		t.Fatalf("无 BOM UTF-16LE：passwordcomplexity = %q, want 1", m["passwordcomplexity"])
	}
	m2 := ParseSeceditInf([]byte(seceditSample))
	if m2["passwordcomplexity"] != "1" {
		t.Fatalf("ASCII：passwordcomplexity = %q, want 1", m2["passwordcomplexity"])
	}
}

func TestParseSeceditInfMissing(t *testing.T) {
	m := ParseSeceditInf([]byte("[Unicode]\nUnicode=yes\n"))
	if len(m) != 0 {
		t.Fatalf("无 [System Access] 段应返回空 map，实际 %v", m)
	}
	m2 := ParseSeceditInf(encodeUTF16LE("[System Access]\nMinimumPasswordLength = 7\n", true))
	if _, ok := m2["passwordcomplexity"]; ok {
		t.Fatalf("缺 PasswordComplexity 键时不应有该键，实际 %v", m2)
	}
	m3 := ParseSeceditInf([]byte("[system access]\nPasswordComplexity = \"0\"\n"))
	if m3["passwordcomplexity"] != "0" {
		t.Fatalf("段名大小写不敏感、值去引号：passwordcomplexity = %q, want 0", m3["passwordcomplexity"])
	}
}
