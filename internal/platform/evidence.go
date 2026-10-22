package platform

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// 证据加密存储（M4-3b）：导入的原始事实包 zip 以 AES-256-GCM 加密落库，
// 方案要求“加密文件存储”。blob 格式：
//
//	"MAE1" | key_version uint16 BE | nonce 12B | GCM ciphertext(含 tag)
//
// 密钥环支持历史版本：当前版本用于加密，全部版本均可解密，
// 以便轮换密钥后旧证据仍可验。key_version=0 表示未加密（仅兼容读，不再写入）。
//
// 环境变量：
//   MEDAUDIT_EVIDENCE_KEY          当前版本密钥（base64，32 字节）
//   MEDAUDIT_EVIDENCE_KEY_VERSION  当前版本号（默认 1）
//   MEDAUDIT_EVIDENCE_KEY_V<n>     历史版本密钥（仅解密）
//
// 未配置当前密钥时证据加密禁用（导入照常，证据不落库，启动日志明示）。

var ErrEvidenceNotFound = errors.New("证据不存在")
var ErrEvidenceKeyMissing = errors.New("证据密钥版本缺失")

const evidenceMagic = "MAE1"

// EvidenceKeyring 版本化 AES-256 密钥环。
type EvidenceKeyring struct {
	current uint16
	keys    map[uint16][]byte
}

// NewEvidenceKeyring 由版本→密钥（各 32 字节）构造密钥环。
func NewEvidenceKeyring(current uint16, keys map[uint16][]byte) (*EvidenceKeyring, error) {
	for v, k := range keys {
		if len(k) != 32 {
			return nil, fmt.Errorf("证据密钥版本 %d 长度 %d，必须为 32 字节", v, len(k))
		}
	}
	if _, ok := keys[current]; !ok {
		return nil, fmt.Errorf("证据当前密钥版本 %d 未提供", current)
	}
	cp := make(map[uint16][]byte, len(keys))
	for v, k := range keys {
		dup := make([]byte, len(k))
		copy(dup, k)
		cp[v] = dup
	}
	return &EvidenceKeyring{current: current, keys: cp}, nil
}

// LoadEvidenceKeyringFromEnv 从环境变量装配密钥环；未配置当前密钥时返回 (nil, nil)。
func LoadEvidenceKeyringFromEnv() (*EvidenceKeyring, error) {
	return loadEvidenceKeyring(os.Getenv)
}

func loadEvidenceKeyring(getenv func(string) string) (*EvidenceKeyring, error) {
	raw := strings.TrimSpace(getenv("MEDAUDIT_EVIDENCE_KEY"))
	if raw == "" {
		return nil, nil
	}
	cur := uint16(1)
	if s := strings.TrimSpace(getenv("MEDAUDIT_EVIDENCE_KEY_VERSION")); s != "" {
		n, err := strconv.ParseUint(s, 10, 16)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("MEDAUDIT_EVIDENCE_KEY_VERSION 非法: %q", s)
		}
		cur = uint16(n)
	}
	keys := map[uint16][]byte{}
	k, err := decodeEvidenceKey(raw)
	if err != nil {
		return nil, fmt.Errorf("MEDAUDIT_EVIDENCE_KEY: %w", err)
	}
	keys[cur] = k
	// 历史版本密钥（仅解密用）：MEDAUDIT_EVIDENCE_KEY_V<n>，扫描 1..64 足够。
	for v := uint16(1); v <= 64; v++ {
		if v == cur {
			continue
		}
		s := strings.TrimSpace(getenv(fmt.Sprintf("MEDAUDIT_EVIDENCE_KEY_V%d", v)))
		if s == "" {
			continue
		}
		hk, err := decodeEvidenceKey(s)
		if err != nil {
			return nil, fmt.Errorf("MEDAUDIT_EVIDENCE_KEY_V%d: %w", v, err)
		}
		keys[v] = hk
	}
	return NewEvidenceKeyring(cur, keys)
}

func decodeEvidenceKey(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 解码失败: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("密钥长度 %d，必须为 32 字节（AES-256）", len(b))
	}
	return b, nil
}

// CurrentVersion 当前加密版本号。
func (k *EvidenceKeyring) CurrentVersion() uint16 { return k.current }

// Encrypt 用当前版本密钥加密，返回完整 blob。
func (k *EvidenceKeyring) Encrypt(plain []byte) ([]byte, error) {
	key, ok := k.keys[k.current]
	if !ok {
		return nil, ErrEvidenceKeyMissing
	}
	gcm, err := evidenceGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	blob := make([]byte, 0, 4+2+len(nonce)+len(plain)+gcm.Overhead())
	blob = append(blob, evidenceMagic...)
	var vb [2]byte
	binary.BigEndian.PutUint16(vb[:], k.current)
	blob = append(blob, vb[:]...)
	blob = append(blob, nonce...)
	blob = gcm.Seal(blob, nonce, plain, nil)
	return blob, nil
}

// Decrypt 按 blob 内版本号选密钥解密；version=0 的明文 blob 原样返回（兼容读）。
func (k *EvidenceKeyring) Decrypt(blob []byte) ([]byte, error) {
	if len(blob) < 6 || string(blob[:4]) != evidenceMagic {
		return blob, nil // 非加密格式：按明文兼容返回
	}
	ver := binary.BigEndian.Uint16(blob[4:6])
	if ver == 0 {
		return blob[6:], nil
	}
	key, ok := k.keys[ver]
	if !ok {
		return nil, fmt.Errorf("%w: v%d", ErrEvidenceKeyMissing, ver)
	}
	gcm, err := evidenceGCM(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < 6+ns {
		return nil, errors.New("证据 blob 截断")
	}
	return gcm.Open(nil, blob[6:6+ns], blob[6+ns:], nil)
}

func evidenceGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// StoreEvidence 加密并保存某事实包的原始 zip 证据，同时回填 fact_bundles.evidence_digest。
// 在调用方事务内执行（tx 与 db 二选一由签名固定为 *sql.Tx 更安全，这里用 ExecContext 兼容接口）。
func StoreEvidence(tx *sql.Tx, kr *EvidenceKeyring, bundleID string, zipBytes []byte) error {
	sum := sha256.Sum256(zipBytes)
	digest := hex.EncodeToString(sum[:])
	blob, err := kr.Encrypt(zipBytes)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO fact_bundle_evidence (bundle_id, key_version, sha256, ciphertext)
		 VALUES (?, ?, ?, ?)`,
		bundleID, kr.CurrentVersion(), digest, blob,
	); err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE fact_bundles SET evidence_digest = ? WHERE id = ?`, digest, bundleID)
	return err
}

// FetchEvidence 读取并解密证据，返回原始 zip 字节与明文 SHA-256。
func FetchEvidence(db *sql.DB, kr *EvidenceKeyring, bundleID string) ([]byte, string, error) {
	var blob []byte
	var digest string
	err := db.QueryRow(
		`SELECT ciphertext, sha256 FROM fact_bundle_evidence WHERE bundle_id = ?`, bundleID,
	).Scan(&blob, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrEvidenceNotFound
	}
	if err != nil {
		return nil, "", err
	}
	if kr == nil {
		return nil, "", errors.New("证据密钥未配置，无法解密")
	}
	plain, err := kr.Decrypt(blob)
	if err != nil {
		return nil, "", err
	}
	// 解密后复核摘要，防止存储层篡改/损坏被静默接受。
	sum := sha256.Sum256(plain)
	if hex.EncodeToString(sum[:]) != digest {
		return nil, "", errors.New("证据摘要复核失败：解密内容与存档 SHA-256 不一致")
	}
	return plain, digest, nil
}
