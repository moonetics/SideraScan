package roblox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

func TestCollectDetectsOfficialRobloxAndBloxstrap(t *testing.T) {
	root := t.TempDir()
	localAppData := filepath.Join(root, "LocalAppData")
	writeFixture(t, filepath.Join(localAppData, "Roblox", "Versions", "version-abc", "RobloxPlayerBeta.exe"), "official")
	writeFixture(t, filepath.Join(localAppData, "Bloxstrap", "Bloxstrap.exe"), "bloxstrap")

	snapshot := Collect(context.Background(), Options{
		LocalAppData: localAppData,
		UserProfile:  filepath.Join(root, "User"),
		ProcessTimeline: []map[string]any{
			{
				"processName": "Bloxstrap.exe",
				"path":        filepath.Join(localAppData, "Bloxstrap", "Bloxstrap.exe"),
				"startTime":   "2026-08-13T01:00:00Z",
				"status":      "running",
			},
		},
	})

	if len(snapshot.LauncherProfiles) < 2 {
		t.Fatalf("expected official Roblox and Bloxstrap profiles, got %d", len(snapshot.LauncherProfiles))
	}
	if !hasLauncher(snapshot, "official_roblox") {
		t.Fatal("expected official Roblox launcher profile")
	}
	bloxstrap := launcherByType(snapshot, "bloxstrap")
	if bloxstrap == nil {
		t.Fatal("expected Bloxstrap launcher profile")
	}
	if bloxstrap.Status == "suspicious" || bloxstrap.Status == "severe" || bloxstrap.Status == "flagged" {
		t.Fatalf("Bloxstrap must not be auto severe/suspicious, got status %q", bloxstrap.Status)
	}
}

func TestClientAssetSummaryMarksRiskyExtensionSuspiciousOnly(t *testing.T) {
	root := t.TempDir()
	localAppData := filepath.Join(root, "LocalAppData")
	writeFixture(t, filepath.Join(localAppData, "Bloxstrap", "Bloxstrap.exe"), "bloxstrap")
	writeFixture(t, filepath.Join(localAppData, "Bloxstrap", "Modifications", "custom.dll"), "metadata only")

	snapshot := Collect(context.Background(), Options{LocalAppData: localAppData, UserProfile: filepath.Join(root, "User")})
	if len(snapshot.ClientModAssets) == 0 {
		t.Fatal("expected client mod asset summary")
	}

	var found bool
	for _, asset := range snapshot.ClientModAssets {
		if asset.Name == "Bloxstrap Modifications" {
			found = true
			if asset.Status != "suspicious" {
				t.Fatalf("expected risky extension to mark asset suspicious, got %q metadata=%v fileCount=%d path=%q", asset.Status, asset.Metadata, asset.FileCount, asset.Path)
			}
			if strings.Contains(strings.ToLower(asset.Status), "severe") {
				t.Fatalf("asset status must not be severe: %q", asset.Status)
			}
		}
	}
	if !found {
		t.Fatal("expected Bloxstrap Modifications asset")
	}
}

func TestCollectProcessTimesFromProcessTimeline(t *testing.T) {
	now := time.Date(2026, 8, 13, 1, 1, 0, 0, time.UTC)
	rows := collectProcessTimes([]map[string]any{
		{
			"processName": "RobloxPlayerBeta.exe",
			"path":        `C:\Users\***\AppData\Local\Roblox\Versions\version-x\RobloxPlayerBeta.exe`,
			"startTime":   "2026-08-13T01:00:00Z",
			"status":      "running",
			"pid":         int32(123),
		},
		{"processName": "notepad.exe"},
	}, now)

	if len(rows) != 1 {
		t.Fatalf("expected one Roblox process time, got %d", len(rows))
	}
	if rows[0].DurationMs != 60000 {
		t.Fatalf("expected 60s duration, got %d", rows[0].DurationMs)
	}
	if rows[0].Source != "live_process" {
		t.Fatalf("expected live_process source, got %q", rows[0].Source)
	}
}

func TestRenameMoveFileLogRequiresOldAndNewPath(t *testing.T) {
	log := fileLog("renamed_file", "", `C:\Users\Alice\Downloads\old.exe`, "", time.Date(2026, 8, 13, 1, 0, 0, 0, time.UTC), "test", 80, "", "INFO", nil)
	if log.Action != "unknown" {
		t.Fatalf("expected incomplete rename to become unknown, got %q", log.Action)
	}

	complete := fileLog("moved_file", "", `C:\Users\Alice\Downloads\old.exe`, `C:\Users\Alice\Downloads\new.exe`, time.Date(2026, 8, 13, 1, 0, 0, 0, time.UTC), "test", 80, "", "INFO", nil)
	if complete.Action != "moved_file" {
		t.Fatalf("expected complete move to stay moved_file, got %q", complete.Action)
	}
	if strings.Contains(complete.OldPath, "Alice") || strings.Contains(complete.NewPath, "Alice") {
		t.Fatalf("expected private path masking, got old=%q new=%q", complete.OldPath, complete.NewPath)
	}
}

func TestSnapshotJSONDoesNotContainForbiddenPrivateStrings(t *testing.T) {
	log := fileLog("downloaded_file", `C:\Users\Alice\Downloads\RobloxTool.exe`, "", "", time.Date(2026, 8, 13, 1, 0, 0, 0, time.UTC), "test", 60, "", "INFO", map[string]any{
		"password": "secret",
		"cookie":   "secret",
	})
	bytes, err := json.Marshal(log)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(bytes))
	for _, forbidden := range []string{"alice", "secret"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("file log json contains forbidden string %q: %s", forbidden, text)
		}
	}
}

func writeFixture(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func hasLauncher(snapshot Snapshot, launcherType string) bool {
	return launcherByType(snapshot, launcherType) != nil
}

func launcherByType(snapshot Snapshot, launcherType string) *contract.LauncherProfile {
	for index := range snapshot.LauncherProfiles {
		if snapshot.LauncherProfiles[index].LauncherType == launcherType {
			return &snapshot.LauncherProfiles[index]
		}
	}
	return nil
}
