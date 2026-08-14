//go:build !windows

package windows

import "context"

func collectBaseline(ctx context.Context, options BaselineOptions) BaselineSnapshot {
	_ = ctx
	_ = options
	return BaselineSnapshot{
		ProcessTimeline: []map[string]any{},
		Utilities:       []map[string]any{},
		WindowsItems: []map[string]any{
			{
				"kind":      "windows_baseline",
				"name":      "Windows baseline",
				"status":    "unsupported",
				"source":    "unsupported_platform",
				"errorCode": "UNSUPPORTED_PLATFORM",
			},
		},
		PartialErrors: []string{"unsupported_platform"},
	}
}
