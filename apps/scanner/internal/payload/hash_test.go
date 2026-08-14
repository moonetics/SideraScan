package payload

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

func TestHashUploadPayloadStableAndIgnoresUploadSecrets(t *testing.T) {
	first, err := HashUploadPayload(contract.UploadResultsRequest{
		UploadToken: "upload-a",
		Nonce:       "nonce-a",
		Overview: map[string]any{
			"os": "Windows",
		},
	})
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	second, err := HashUploadPayload(contract.UploadResultsRequest{
		UploadToken: "upload-b",
		Nonce:       "nonce-b",
		Overview: map[string]any{
			"os": "Windows",
		},
	})
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	if first != second {
		t.Fatalf("expected hash to ignore upload secrets")
	}
}

func TestCompactForBudgetTrimsTimelineAndPreservesCore(t *testing.T) {
	request := contract.UploadResultsRequest{
		UploadToken: "upload-secret",
		Nonce:       "nonce-secret",
		Overview:    map[string]any{"os": "Windows"},
		DeviceFingerprint: &contract.DeviceFingerprint{
			Hash:       strings.Repeat("a", 64),
			Version:    "test",
			Confidence: "HIGH",
		},
		Evidence: []contract.Evidence{{ClientEvidenceID: "ev_1", Type: "test", Title: "Evidence"}},
		Findings: []contract.Finding{{Title: "Finding", Message: "Message", EvidenceRef: "ev_1"}},
	}
	for i := 0; i < 40; i++ {
		request.ForensicTimeline = append(request.ForensicTimeline, map[string]any{
			"id":           i,
			"title":        "timeline row",
			"severity":     "INFO",
			"metadata":     map[string]any{"large": strings.Repeat("x", 256)},
			"evidenceRefs": []string{},
		})
	}
	request.ForensicTimeline[20]["severity"] = "SEVERE"
	request.ForensicTimeline[20]["correlationId"] = "corr_keep"
	request.DNSCache = []map[string]any{{"domain": "roblox.com", "status": "context"}}

	report := CompactForBudget(&request, Budget{MaxPayloadBytes: 2500, MaxTimelineRows: 10})
	if !report.Trimmed {
		t.Fatal("expected payload to be trimmed")
	}
	if len(request.ForensicTimeline) > 10 {
		t.Fatalf("expected timeline capped, got %d", len(request.ForensicTimeline))
	}
	if request.Overview["os"] != "Windows" || request.DeviceFingerprint == nil || len(request.Evidence) != 1 || len(request.Findings) != 1 {
		t.Fatalf("core fields were trimmed: %+v", request)
	}
	foundCorrelation := false
	for _, row := range request.ForensicTimeline {
		if row["correlationId"] == "corr_keep" {
			foundCorrelation = true
		}
		if _, hasMetadata := row["metadata"]; hasMetadata {
			t.Fatalf("timeline metadata should be compacted: %#v", row)
		}
	}
	if !foundCorrelation {
		t.Fatal("expected high-signal correlation row to survive compaction")
	}
	if request.Integrity["payloadTrimmed"] != true {
		t.Fatalf("expected payloadTrimmed telemetry, got %#v", request.Integrity)
	}
	raw, err := json.Marshal(request.Integrity)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"upload-secret", "nonce-secret", "scannerKey", "MachineGuid"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("trim telemetry leaked %q in %s", forbidden, raw)
		}
	}
}

func TestForceCompactTrimsContextBeforeRetry(t *testing.T) {
	request := contract.UploadResultsRequest{}
	for i := 0; i < 220; i++ {
		request.ForensicTimeline = append(request.ForensicTimeline, map[string]any{"id": i, "severity": "INFO", "metadata": map[string]any{"large": strings.Repeat("x", 128)}})
		request.NetworkConnections = append(request.NetworkConnections, map[string]any{"forensicSource": "usb_history", "status": "context"})
	}
	report := ForceCompact(&request, Budget{})
	if !report.Trimmed {
		t.Fatal("expected force compact trim report")
	}
	if len(request.ForensicTimeline) > 100 {
		t.Fatalf("expected force compact timeline <=100, got %d", len(request.ForensicTimeline))
	}
	if len(request.NetworkConnections) > 80 {
		t.Fatalf("expected force compact network <=80, got %d", len(request.NetworkConnections))
	}
}

func TestHashUploadPayloadChangesWithContent(t *testing.T) {
	first, _ := HashUploadPayload(contract.UploadResultsRequest{
		Overview: map[string]any{"os": "Windows"},
	})
	second, _ := HashUploadPayload(contract.UploadResultsRequest{
		Overview: map[string]any{"os": "Linux"},
	})

	if first == second {
		t.Fatal("expected content changes to change hash")
	}
}
