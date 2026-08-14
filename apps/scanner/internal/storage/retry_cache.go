package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	scannercrypto "github.com/moonetics/SideraScan/apps/scanner/internal/crypto"
)

const Retention = 24 * time.Hour

type Protector interface {
	Protect([]byte) ([]byte, error)
	Unprotect([]byte) ([]byte, error)
}

type RetryCache struct {
	root      string
	protector Protector
	now       func() time.Time
}

type CacheMetadata struct {
	ScanSessionID string    `json:"scanSessionId"`
	AccountName   string    `json:"accountName,omitempty"`
	PayloadHash   string    `json:"payloadHash"`
	ExpiresAt     time.Time `json:"expiresAt"`
	CreatedAt     time.Time `json:"createdAt"`
	RetryCount    int       `json:"retryCount"`
}

type CachedPayload struct {
	Metadata CacheMetadata
	Payload  []byte
}

func NewRetryCache(protector Protector) RetryCache {
	return RetryCache{
		root:      filepath.Join(os.TempDir(), "SideraScan", "sessions"),
		protector: protector,
		now:       time.Now,
	}
}

func NewDefaultRetryCache() RetryCache {
	return NewRetryCache(scannercrypto.NewProtector())
}

func NewRetryCacheAt(root string, protector Protector, now func() time.Time) RetryCache {
	if now == nil {
		now = time.Now
	}

	return RetryCache{
		root:      root,
		protector: protector,
		now:       now,
	}
}

func (c RetryCache) Save(metadata CacheMetadata, payload []byte) error {
	if metadata.ScanSessionID == "" {
		return errors.New("scan session id is required")
	}
	if !metadata.ExpiresAt.IsZero() && !metadata.ExpiresAt.After(c.now()) {
		return errors.New("upload session expired")
	}
	if c.protector == nil {
		return scannercrypto.ErrUnsupported
	}

	metadata.CreatedAt = nonZeroTime(metadata.CreatedAt, c.now())
	encrypted, err := c.protector.Protect(payload)
	if err != nil {
		return fmt.Errorf("protect payload: %w", err)
	}

	dir := c.sessionDir(metadata.ScanSessionID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(dir, "payload.enc"), encrypted, 0o600); err != nil {
		return err
	}

	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		_ = c.Delete(metadata.ScanSessionID)
		return err
	}

	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), metadataBytes, 0o600); err != nil {
		_ = c.Delete(metadata.ScanSessionID)
		return err
	}

	return nil
}

func (c RetryCache) Load(scanSessionID string) (CachedPayload, error) {
	metadataBytes, err := os.ReadFile(filepath.Join(c.sessionDir(scanSessionID), "metadata.json"))
	if err != nil {
		return CachedPayload{}, err
	}

	var metadata CacheMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return CachedPayload{}, err
	}

	if c.IsExpired(metadata) {
		_ = c.Delete(scanSessionID)
		return CachedPayload{}, errors.New("cached payload expired")
	}

	encrypted, err := os.ReadFile(filepath.Join(c.sessionDir(scanSessionID), "payload.enc"))
	if err != nil {
		return CachedPayload{}, err
	}
	if c.protector == nil {
		return CachedPayload{}, scannercrypto.ErrUnsupported
	}

	payload, err := c.protector.Unprotect(encrypted)
	if err != nil {
		return CachedPayload{}, fmt.Errorf("unprotect payload: %w", err)
	}

	return CachedPayload{Metadata: metadata, Payload: payload}, nil
}

func (c RetryCache) Delete(scanSessionID string) error {
	return os.RemoveAll(c.sessionDir(scanSessionID))
}

func (c RetryCache) CleanupExpired() error {
	entries, err := os.ReadDir(c.root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		metadataBytes, err := os.ReadFile(filepath.Join(c.root, entry.Name(), "metadata.json"))
		if err != nil {
			continue
		}

		var metadata CacheMetadata
		if err := json.Unmarshal(metadataBytes, &metadata); err != nil || c.IsExpired(metadata) || metadata.ScanSessionID != entry.Name() {
			_ = os.RemoveAll(filepath.Join(c.root, entry.Name()))
		}
	}

	return nil
}

func (c RetryCache) IsExpired(metadata CacheMetadata) bool {
	now := c.now()
	if !metadata.ExpiresAt.IsZero() && !metadata.ExpiresAt.After(now) {
		return true
	}
	if metadata.CreatedAt.IsZero() {
		return false
	}

	return now.Sub(metadata.CreatedAt) > Retention
}

func (c RetryCache) sessionDir(scanSessionID string) string {
	return filepath.Join(c.root, filepath.Base(filepath.Clean(scanSessionID)))
}

func nonZeroTime(value time.Time, fallback time.Time) time.Time {
	if value.IsZero() {
		return fallback
	}

	return value
}
