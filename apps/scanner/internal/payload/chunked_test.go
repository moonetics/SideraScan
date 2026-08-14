package payload

import (
	"testing"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

func TestCoreUploadRequestRemovesLargeSections(t *testing.T) {
	request := contract.UploadResultsRequest{
		UploadToken:      "sut_test",
		Nonce:            "snonce_test",
		Overview:         map[string]any{"os": "Windows"},
		ProcessTimeline:  []map[string]any{{"processName": "RobloxPlayerBeta.exe"}},
		EventLogs:        []map[string]any{{"eventId": 1102}},
		ForensicTimeline: []map[string]any{{"title": "correlation"}},
		Findings:         []contract.Finding{{Title: "finding", Message: "message"}},
	}

	core := CoreUploadRequest(request, []string{"processTimeline", "eventLogs", "forensicTimeline"})

	if len(core.ProcessTimeline) != 0 || len(core.EventLogs) != 0 || len(core.ForensicTimeline) != 0 {
		t.Fatal("core upload should not include large section rows")
	}
	if len(core.Findings) != 1 {
		t.Fatal("core upload must preserve findings")
	}
	if core.Integrity["uploadMode"] != "chunked" {
		t.Fatal("core upload should mark chunked mode")
	}
}

func TestUploadSectionsAndSplitSection(t *testing.T) {
	request := contract.UploadResultsRequest{
		ProcessTimeline: []map[string]any{
			{"processName": "a.exe", "path": `C:\Users\***\a.exe`},
			{"processName": "b.exe", "path": `C:\Users\***\b.exe`},
		},
		DNSCache: []map[string]any{{"domain": "example.test"}},
	}

	sections := UploadSections(request)
	if len(sections) != 2 {
		t.Fatalf("expected two sections, got %d", len(sections))
	}
	chunks := SplitSection(sections[0], 80)
	if len(chunks) < 1 {
		t.Fatal("expected at least one chunk")
	}
	for _, chunk := range chunks {
		if chunk.Section != "processTimeline" {
			t.Fatalf("unexpected chunk section %q", chunk.Section)
		}
		if chunk.TotalItems != 2 {
			t.Fatalf("expected total item count to stay 2, got %d", chunk.TotalItems)
		}
		if chunk.PayloadHash == "" {
			t.Fatal("chunk should have payload hash")
		}
	}
}
