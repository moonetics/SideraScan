package windows

import (
	"context"
	"time"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

type Snapshot struct {
	Overview          map[string]any
	SystemIdentity    map[string]any
	NetworkSnapshot   map[string]any
	Integrity         map[string]any
	DeviceFingerprint *contract.DeviceFingerprint
	PartialErrors     []string
}

type CollectOptions struct {
	ScanSessionID string
	StartedAt     time.Time
	FinishedAt    time.Time
}

func CollectSnapshot(ctx context.Context, options CollectOptions) Snapshot {
	return collectSnapshot(ctx, options)
}
