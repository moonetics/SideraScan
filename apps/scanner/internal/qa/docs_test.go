package qa

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseDocsCoverProductionGate(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	releaseDocs, err := os.ReadFile(filepath.Join(root, "docs", "RELEASE_CHECKLIST.md"))
	if err != nil {
		t.Fatalf("read release checklist: %v", err)
	}
	text := strings.ToLower(string(releaseDocs))
	for _, required := range []string{
		"checksum",
		"signing",
		"smoke test",
		"/scans",
		"privacy",
		"https",
		"minimum backend supported",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("release checklist missing %q", required)
		}
	}
}
