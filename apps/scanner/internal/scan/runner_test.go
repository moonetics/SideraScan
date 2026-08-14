package scan

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/moonetics/SideraScan/apps/scanner/internal/progress"
)

func TestRunnerRecordsDurationAndStatus(t *testing.T) {
	runner := NewRunner([]Module{
		{Name: "ok", Stage: progress.StageOverview},
	})
	results := runner.Run(context.Background(), RunContext{Started: time.Now()}, progress.NewTracker(), nil)

	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}
	if results[0].Status != StatusCompleted {
		t.Fatalf("expected completed, got %s", results[0].Status)
	}
	if results[0].Duration <= 0 {
		t.Fatal("expected duration")
	}
}

func TestRunnerConvertsModuleFailureToPartial(t *testing.T) {
	runner := NewRunner([]Module{
		{
			Name:  "partial",
			Stage: progress.StageOverview,
			Run: func(context.Context, RunContext) error {
				return errors.New("uploadToken leaked in original error")
			},
		},
	})
	results := runner.Run(context.Background(), RunContext{Started: time.Now()}, progress.NewTracker(), nil)

	if results[0].Status != StatusPartial {
		t.Fatalf("expected partial, got %s", results[0].Status)
	}
	if results[0].ErrorCode == "" {
		t.Fatal("expected error code")
	}
	if results[0].ErrorMessage == "uploadToken leaked in original error" {
		t.Fatal("expected redacted error")
	}
}

func TestRunnerKeepsWarningsCompleted(t *testing.T) {
	runner := NewRunner([]Module{
		{
			Name:  "warning",
			Stage: progress.StageOverview,
			Run: func(context.Context, RunContext) error {
				return Warning("defender_summary_unavailable")
			},
		},
	})
	results := runner.Run(context.Background(), RunContext{Started: time.Now()}, progress.NewTracker(), nil)

	if results[0].Status != StatusCompleted {
		t.Fatalf("expected completed warning, got %s", results[0].Status)
	}
	if results[0].ErrorCode != "MODULE_WARNING" {
		t.Fatalf("expected module warning code, got %q", results[0].ErrorCode)
	}
}

func TestOverallStatus(t *testing.T) {
	if got := OverallStatus([]ModuleResult{{Status: StatusCompleted}}); got != "COMPLETED" {
		t.Fatalf("expected completed, got %s", got)
	}
	if got := OverallStatus([]ModuleResult{{Status: StatusCompleted, ErrorCode: "MODULE_WARNING"}}); got != "COMPLETED" {
		t.Fatalf("expected completed for warning-only module, got %s", got)
	}
	if got := OverallStatus([]ModuleResult{{Status: StatusPartial}}); got != "PARTIAL" {
		t.Fatalf("expected partial, got %s", got)
	}
}
