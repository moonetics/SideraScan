package qa

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScannerRuntimeDoesNotReferenceN8N(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	forbidden := []string{
		"n8n",
		"/webhook/",
		"localhost:5678",
		"webhook/siderascan",
	}
	runtimeRoots := []string{
		filepath.Join(root, "cmd"),
		filepath.Join(root, "internal"),
	}

	for _, runtimeRoot := range runtimeRoots {
		err := filepath.WalkDir(runtimeRoot, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			lower := strings.ToLower(string(content))
			for _, token := range forbidden {
				if strings.Contains(lower, token) {
					t.Fatalf("scanner runtime source must not reference %q directly: %s", token, path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan runtime source for n8n references: %v", err)
		}
	}
}
