package storage

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	scannercrypto "github.com/moonetics/SideraScan/apps/scanner/internal/crypto"
)

type fakeProtector struct {
	fail bool
}

func (p fakeProtector) Protect(input []byte) ([]byte, error) {
	if p.fail {
		return nil, errors.New("protect failed")
	}
	output := append([]byte("encrypted:"), input...)
	for i := len("encrypted:"); i < len(output); i++ {
		output[i] ^= 0x42
	}
	return output, nil
}

func (p fakeProtector) Unprotect(input []byte) ([]byte, error) {
	if p.fail {
		return nil, errors.New("unprotect failed")
	}
	output := append([]byte(nil), input[len("encrypted:"):]...)
	for i := range output {
		output[i] ^= 0x42
	}
	return output, nil
}

func TestRetryCacheWritesEncryptedPayloadAndSafeMetadata(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 8, 13, 1, 0, 0, 0, time.UTC)
	cache := NewRetryCacheAt(root, fakeProtector{}, func() time.Time { return now })
	payload := []byte(`{"uploadToken":"secret-upload","nonce":"secret-nonce","overview":{"os":"Windows"}}`)

	err := cache.Save(CacheMetadata{
		ScanSessionID: "scan_1",
		AccountName:   "Account",
		PayloadHash:   "hash",
		ExpiresAt:     now.Add(time.Hour),
	}, payload)
	if err != nil {
		t.Fatalf("save failed: %v", err)
	}

	encrypted, err := os.ReadFile(filepath.Join(root, "scan_1", "payload.enc"))
	if err != nil {
		t.Fatalf("read encrypted payload: %v", err)
	}
	if bytes.Contains(encrypted, []byte("secret-upload")) || bytes.Contains(encrypted, []byte("secret-nonce")) {
		t.Fatalf("encrypted payload leaked plaintext secrets: %s", string(encrypted))
	}

	metadata, err := os.ReadFile(filepath.Join(root, "scan_1", "metadata.json"))
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	if bytes.Contains(metadata, []byte("secret-upload")) || bytes.Contains(metadata, []byte("secret-nonce")) {
		t.Fatalf("metadata leaked upload secrets: %s", string(metadata))
	}
	for _, forbidden := range [][]byte{
		[]byte("scannerKey"),
		[]byte("machineGuid"),
		[]byte("serialNumber"),
		[]byte("password"),
		[]byte("cookie"),
		[]byte("clipboard"),
		[]byte("screenshot"),
	} {
		if bytes.Contains(metadata, forbidden) {
			t.Fatalf("metadata contained forbidden field %q: %s", forbidden, string(metadata))
		}
	}

	loaded, err := cache.Load("scan_1")
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if !bytes.Equal(loaded.Payload, payload) {
		t.Fatalf("loaded payload mismatch: %s", string(loaded.Payload))
	}
}

func TestRetryCacheRefusesExpiredSession(t *testing.T) {
	now := time.Date(2026, 8, 13, 1, 0, 0, 0, time.UTC)
	cache := NewRetryCacheAt(t.TempDir(), fakeProtector{}, func() time.Time { return now })

	err := cache.Save(CacheMetadata{
		ScanSessionID: "scan_1",
		ExpiresAt:     now.Add(-time.Second),
	}, []byte(`{}`))
	if err == nil {
		t.Fatal("expected expired session to be refused")
	}
}

func TestRetryCacheRefusesUnsupportedProtector(t *testing.T) {
	now := time.Date(2026, 8, 13, 1, 0, 0, 0, time.UTC)
	cache := NewRetryCacheAt(t.TempDir(), scannercrypto.UnsupportedProtector{}, func() time.Time { return now })

	err := cache.Save(CacheMetadata{
		ScanSessionID: "scan_1",
		ExpiresAt:     now.Add(time.Hour),
	}, []byte(`{}`))
	if !errors.Is(err, scannercrypto.ErrUnsupported) {
		t.Fatalf("expected unsupported error, got %v", err)
	}
}

func TestRetryCacheCleanupExpired(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 8, 13, 1, 0, 0, 0, time.UTC)
	cache := NewRetryCacheAt(root, fakeProtector{}, func() time.Time { return now })

	err := cache.Save(CacheMetadata{
		ScanSessionID: "scan_1",
		CreatedAt:     now.Add(-25 * time.Hour),
		ExpiresAt:     now.Add(time.Hour),
	}, []byte(`{}`))
	if err != nil {
		t.Fatalf("save failed: %v", err)
	}

	if err := cache.CleanupExpired(); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "scan_1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected cache directory deleted, got %v", err)
	}
}

func TestRetryCacheCleanupDeletesCorruptMetadata(t *testing.T) {
	root := t.TempDir()
	cache := NewRetryCacheAt(root, fakeProtector{}, func() time.Time { return time.Date(2026, 8, 13, 1, 0, 0, 0, time.UTC) })
	dir := filepath.Join(root, "scan_1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), []byte(`{bad json`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cache.CleanupExpired(); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected corrupt cache deleted, got %v", err)
	}
}

func TestRetryCacheSessionDirBlocksTraversal(t *testing.T) {
	root := t.TempDir()
	cache := NewRetryCacheAt(root, fakeProtector{}, time.Now)
	dir := cache.sessionDir(`..\outside`)

	if filepath.Dir(dir) != root {
		t.Fatalf("expected session dir to stay under cache root, got %q", dir)
	}
	if filepath.Base(dir) != "outside" {
		t.Fatalf("expected sanitized base path, got %q", dir)
	}
}
