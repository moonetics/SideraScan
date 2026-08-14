package fingerprint

import (
	"strings"
	"testing"
)

func TestBuildStableAndChangesWithSignals(t *testing.T) {
	signals := []Signal{
		{Name: "cpu_name", Value: "CPU"},
		{Name: "machine_guid", Value: "raw-guid"},
		{Name: "gpu_name", Value: "GPU"},
		{Name: "disk_model", Value: "Disk"},
	}
	first := Build(signals)
	second := Build([]Signal{
		{Name: "gpu_name", Value: "GPU"},
		{Name: "disk_model", Value: "Disk"},
		{Name: "machine_guid", Value: "raw-guid"},
		{Name: "cpu_name", Value: "CPU"},
	})
	changed := Build([]Signal{
		{Name: "cpu_name", Value: "Other CPU"},
		{Name: "machine_guid", Value: "raw-guid"},
		{Name: "gpu_name", Value: "GPU"},
		{Name: "disk_model", Value: "Disk"},
	})

	if first.Fingerprint.Hash != second.Fingerprint.Hash {
		t.Fatal("fingerprint should be stable regardless of order")
	}
	if first.Fingerprint.Hash == changed.Fingerprint.Hash {
		t.Fatal("fingerprint should change when a signal changes")
	}
}

func TestBuildDoesNotExposeRawSignals(t *testing.T) {
	result := Build([]Signal{
		{Name: "machine_guid", Value: "raw-guid-secret"},
		{Name: "serial", Value: "raw-serial-secret"},
	})

	if strings.Contains(result.Fingerprint.Hash, "raw-guid-secret") || strings.Contains(result.Fingerprint.Hash, "raw-serial-secret") {
		t.Fatalf("fingerprint leaked raw signal: %+v", result)
	}
	for _, signal := range result.SignalsUsed {
		if strings.Contains(signal, "raw") {
			t.Fatalf("signal names leaked raw values: %+v", result.SignalsUsed)
		}
	}
}

func TestConfidence(t *testing.T) {
	low := Build([]Signal{{Name: "cpu_name", Value: "CPU"}})
	if low.Fingerprint.Confidence != "LOW" {
		t.Fatalf("expected low confidence, got %s", low.Fingerprint.Confidence)
	}

	medium := Build([]Signal{
		{Name: "cpu_name", Value: "CPU"},
		{Name: "gpu_name", Value: "GPU"},
	})
	if medium.Fingerprint.Confidence != "MEDIUM" {
		t.Fatalf("expected medium confidence, got %s", medium.Fingerprint.Confidence)
	}

	high := Build([]Signal{
		{Name: "machine_guid", Value: "raw-guid"},
		{Name: "cpu_name", Value: "CPU"},
		{Name: "gpu_name", Value: "GPU"},
		{Name: "disk_model", Value: "Disk"},
	})
	if high.Fingerprint.Confidence != "HIGH" {
		t.Fatalf("expected high confidence, got %s", high.Fingerprint.Confidence)
	}
}
