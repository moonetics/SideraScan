package progress

import "testing"

func TestTrackerUsesDeterministicRanges(t *testing.T) {
	tracker := NewTracker()

	tests := []struct {
		stage    Stage
		fraction float64
		want     float64
	}{
		{StageKeyValidation, 1, 10},
		{StageScannerConfig, 0.5, 15},
		{StageOverview, 1, 30},
		{StageUpload, 1, 99},
		{StageComplete, 1, 100},
	}

	for _, tt := range tests {
		event := tracker.Advance(tt.stage, tt.fraction, string(tt.stage))
		if event.Percent != tt.want {
			t.Fatalf("stage %s got %.1f, want %.1f", tt.stage, event.Percent, tt.want)
		}
	}
}

func TestTrackerDoesNotMoveBackward(t *testing.T) {
	tracker := NewTracker()
	tracker.Advance(StageUpload, 1, "upload")
	event := tracker.Advance(StageOverview, 0, "overview")

	if event.Percent != 99 {
		t.Fatalf("expected monotonic progress, got %.1f", event.Percent)
	}
}
