package facts

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// WriteZip 将事实包写成 zip（内含 bundle.json）。
func WriteZip(path string, b *FactBundle) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return WriteZipBytes(path, data)
}

// WriteZipBytes 将已序列化的 bundle.json 写成 zip。
func WriteZipBytes(path string, data []byte) error {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("bundle.json")
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0644)
}

// ReadZip 从 zip 文件读取事实包。
func ReadZip(path string) (*FactBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ReadZipBytes(data)
}

// ReadZipBytes 从 zip 字节流读取事实包（服务端导入用）。
func ReadZipBytes(data []byte) (*FactBundle, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if f.Name != "bundle.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		raw, err := io.ReadAll(io.LimitReader(rc, 100<<20))
		rc.Close()
		if err != nil {
			return nil, err
		}
		var b FactBundle
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, fmt.Errorf("bundle.json 解析失败: %w", err)
		}
		return &b, nil
	}
	return nil, fmt.Errorf("zip 中没有 bundle.json")
}
