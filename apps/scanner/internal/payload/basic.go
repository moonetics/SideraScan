package payload

import (
	"fmt"
	"runtime"
	"time"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

func BuildBasicResult(session contract.ScannerSession, scannerVersion string, startedAt time.Time, finishedAt time.Time) contract.UploadResultsRequest {
	duration := finishedAt.Sub(startedAt)
	if duration < 0 {
		duration = 0
	}

	osName := runtime.GOOS
	if runtime.GOOS == "windows" {
		osName = "Windows"
	}

	return contract.UploadResultsRequest{
		UploadToken:    session.UploadToken,
		Nonce:          session.Nonce,
		ScannerVersion: scannerVersion,
		StartedAt:      startedAt.UTC().Format(time.RFC3339),
		FinishedAt:     finishedAt.UTC().Format(time.RFC3339),
		Overview: map[string]any{
			"os":             osName,
			"vm":             "Unknown",
			"connectionType": "Unknown",
			"country":        "Unknown",
			"scanSpeed":      formatDuration(duration),
			"date":           finishedAt.UTC().Format(time.RFC3339),
		},
		SystemIdentity: map[string]any{
			"os":   osName,
			"arch": runtime.GOARCH,
		},
		NetworkSnapshot: map[string]any{
			"connectionType": "Unknown",
			"country":        "Unknown",
		},
		Modules: []contract.ModuleResult{
			{
				ModuleName: "overview",
				Status:     "completed",
				DurationMs: duration.Milliseconds(),
			},
		},
		AuditLog: []map[string]any{
			{
				"action":    "scanner_result_prepared",
				"source":    "siderascan_scanner",
				"createdAt": finishedAt.UTC().Format(time.RFC3339),
			},
		},
	}
}

func formatDuration(duration time.Duration) string {
	seconds := int(duration.Round(time.Second).Seconds())
	if seconds < 1 {
		seconds = 1
	}

	return fmt.Sprintf("%ds", seconds)
}
