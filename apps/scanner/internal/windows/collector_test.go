package windows

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCollectSnapshotDoesNotExposeForbiddenValues(t *testing.T) {
	snapshot := CollectSnapshot(context.Background(), CollectOptions{
		ScanSessionID: "scan_1",
		StartedAt:     time.Date(2026, 8, 13, 1, 0, 0, 0, time.UTC),
		FinishedAt:    time.Date(2026, 8, 13, 1, 0, 5, 0, time.UTC),
	})

	bytes, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	body := strings.ToLower(string(bytes))

	forbidden := []string{
		"machineguid",
		"machine guid",
		"serialnumber",
		"serial number",
		"scannerkey",
		"uploadtoken",
		"password",
		"clipboard",
		"cookie",
		"screenshot",
	}
	for _, item := range forbidden {
		if strings.Contains(body, item) {
			t.Fatalf("snapshot leaked forbidden marker %q: %s", item, string(bytes))
		}
	}
}

func TestCollectSnapshotIncludesCoreMaps(t *testing.T) {
	snapshot := CollectSnapshot(context.Background(), CollectOptions{
		ScanSessionID: "scan_1",
		StartedAt:     time.Date(2026, 8, 13, 1, 0, 0, 0, time.UTC),
		FinishedAt:    time.Date(2026, 8, 13, 1, 0, 5, 0, time.UTC),
	})

	if snapshot.Overview["scanSessionId"] != "scan_1" {
		t.Fatalf("expected scan session id in overview: %#v", snapshot.Overview)
	}
	if snapshot.DeviceFingerprint == nil || snapshot.DeviceFingerprint.Hash == "" {
		t.Fatalf("expected device fingerprint: %#v", snapshot.DeviceFingerprint)
	}
	if snapshot.SystemIdentity == nil || snapshot.NetworkSnapshot == nil || snapshot.Integrity == nil {
		t.Fatal("expected all core maps")
	}
}
