package payload

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

func TestSanitizeForUploadRemovesNullBytes(t *testing.T) {
	request := contract.UploadResultsRequest{
		UploadToken: "upload-token",
		Nonce:       "nonce",
		Overview: map[string]any{
			"os": "Windows\x00 11",
			"nested": map[string]any{
				"value": "safe\x00text",
			},
		},
		ProcessTimeline: []map[string]any{
			{"processName": "example\x00.exe"},
		},
	}

	clean, err := SanitizeForUpload(request)
	if err != nil {
		t.Fatalf("sanitize upload: %v", err)
	}

	encoded, err := json.Marshal(clean)
	if err != nil {
		t.Fatalf("marshal clean payload: %v", err)
	}

	if strings.Contains(string(encoded), `\u0000`) || strings.ContainsRune(string(encoded), '\x00') {
		t.Fatalf("payload still contains null byte escape: %s", encoded)
	}

	if clean.Overview["os"] != "Windows 11" {
		t.Fatalf("expected null byte to be removed, got %#v", clean.Overview["os"])
	}
}
