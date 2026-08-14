package payload

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

func TestBuildBasicResultOmitsOwnershipAndScannerKey(t *testing.T) {
	started := time.Date(2026, 8, 13, 1, 2, 3, 0, time.UTC)
	finished := started.Add(3 * time.Second)
	result := BuildBasicResult(contract.ScannerSession{
		AccountID:     "account_must_not_be_sent",
		ScanSessionID: "scan_1",
		UploadToken:   "upload-secret",
		Nonce:         "nonce-secret",
	}, "0.1.0", started, finished)

	bytes, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	body := string(bytes)

	if !strings.Contains(body, `"uploadToken":"upload-secret"`) {
		t.Fatal("expected uploadToken at top level")
	}
	if !strings.Contains(body, `"nonce":"nonce-secret"`) {
		t.Fatal("expected nonce at top level")
	}
	if strings.Contains(body, "account_must_not_be_sent") || strings.Contains(body, "accountId") {
		t.Fatalf("result leaked account ownership data: %s", body)
	}
	if strings.Contains(body, "scannerKey") || strings.Contains(body, "sds_live_") {
		t.Fatalf("result leaked scanner key field/value: %s", body)
	}
}

func TestBuildBasicResultIncludesMinimumScanFields(t *testing.T) {
	started := time.Date(2026, 8, 13, 1, 2, 3, 0, time.UTC)
	finished := started.Add(3 * time.Second)
	result := BuildBasicResult(contract.ScannerSession{
		UploadToken: "upload",
		Nonce:       "nonce",
	}, "0.1.0", started, finished)

	if result.ScannerVersion != "0.1.0" {
		t.Fatalf("expected scanner version, got %q", result.ScannerVersion)
	}
	if len(result.Modules) == 0 {
		t.Fatal("expected modules")
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no placeholder findings, got %d", len(result.Findings))
	}
	if result.StartedAt == "" || result.FinishedAt == "" {
		t.Fatal("expected started and finished timestamps")
	}
}
