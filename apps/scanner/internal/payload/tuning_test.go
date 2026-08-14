package payload

import (
	"testing"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

func TestApplyForensicNoiseTuningDedupesFindingsAndSummarizesContext(t *testing.T) {
	request := contract.UploadResultsRequest{
		ExecutionArtifacts: []map[string]any{
			{
				"name":            "AM_DELTA_PATCH.exe",
				"status":          "context",
				"severity":        "INFO",
				"suspiciousFlags": []string{"benign_defender_update_artifact"},
			},
			{
				"name":            "loader.exe",
				"status":          "review",
				"severity":        "INFO",
				"suspiciousFlags": []string{"downloads_executable"},
			},
		},
		Findings: []contract.Finding{
			{
				Severity:     "WARNING",
				Title:        "Duplicate",
				SourceModule: "execution_artifacts",
				Metadata:     map[string]any{"path": `C:\Users\***\Downloads\tool.exe`, "reasonFlags": []string{"downloads_executable"}},
			},
			{
				Severity:     "WARNING",
				Title:        "Duplicate",
				SourceModule: "execution_artifacts",
				Metadata:     map[string]any{"path": `C:\Users\***\Downloads\tool.exe`, "reasonFlags": []string{"downloads_executable"}},
			},
		},
	}

	ApplyForensicNoiseTuning(&request)

	if len(request.Findings) != 1 {
		t.Fatalf("expected duplicate finding to be collapsed, got %d", len(request.Findings))
	}
	summary, ok := request.Integrity["af8Summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected af8Summary, got %#v", request.Integrity)
	}
	if summary["noiseSuppressedCount"] != 2 {
		t.Fatalf("expected two context/review-only rows, got %#v", summary["noiseSuppressedCount"])
	}
	if summary["benignClassifiedCount"] != 1 {
		t.Fatalf("expected benign count, got %#v", summary["benignClassifiedCount"])
	}
	if summary["dedupedFindings"] != 1 {
		t.Fatalf("expected one deduped finding, got %#v", summary["dedupedFindings"])
	}
}
