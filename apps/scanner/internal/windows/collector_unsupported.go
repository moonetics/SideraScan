//go:build !windows

package windows

import (
	"context"
	"runtime"
	"time"

	"github.com/moonetics/SideraScan/apps/scanner/internal/fingerprint"
)

func collectSnapshot(ctx context.Context, options CollectOptions) Snapshot {
	_ = ctx
	finishedAt := options.FinishedAt
	if finishedAt.IsZero() {
		finishedAt = time.Now().UTC()
	}
	startedAt := options.StartedAt
	if startedAt.IsZero() {
		startedAt = finishedAt
	}

	fp := fingerprint.Build([]fingerprint.Signal{
		{Name: "os", Value: runtime.GOOS},
		{Name: "arch", Value: runtime.GOARCH},
	})

	return Snapshot{
		Overview: map[string]any{
			"scanSessionId":     options.ScanSessionID,
			"os":                runtime.GOOS,
			"arch":              runtime.GOARCH,
			"vm":                "Unknown",
			"connectionType":    "Unknown",
			"country":           "Unknown",
			"installation":      "Unknown",
			"recycleBin":        "Unknown",
			"bootTime":          "Unknown",
			"computerStartedAt": "Unknown",
			"scanSpeed":         finishedAt.Sub(startedAt).String(),
			"date":              finishedAt.UTC().Format(time.RFC3339),
			"runAsAdmin":        false,
			"collectorPartial":  true,
		},
		SystemIdentity: map[string]any{
			"os":                           runtime.GOOS,
			"architecture":                 runtime.GOARCH,
			"deviceFingerprintSignalsUsed": fp.SignalsUsed,
		},
		NetworkSnapshot: map[string]any{
			"connectionType": "Unknown",
			"country":        "Unknown",
		},
		Integrity: map[string]any{
			"runAsAdmin": false,
			"permission": "unsupported_platform",
			"deviceFingerprint": map[string]any{
				"version":     fp.Fingerprint.Version,
				"confidence":  fp.Fingerprint.Confidence,
				"signalsUsed": fp.SignalsUsed,
			},
			"collectorPartial": true,
		},
		DeviceFingerprint: &fp.Fingerprint,
		PartialErrors:     []string{"unsupported_platform"},
	}
}
