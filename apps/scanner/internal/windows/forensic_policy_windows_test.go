//go:build windows

package windows

import "testing"

func TestAF8BenignClassifierCoversNoisyArtifacts(t *testing.T) {
	if !policyIsDefenderUpdateArtifact("AM_DELTA_PATCH_1.421.1.0.exe", `C:\Windows\Prefetch\AM_DELTA_PATCH_1.421.1.0.pf`) {
		t.Fatal("expected Defender AM_DELTA artifact to be benign context")
	}
	if !policyIsDefenderUpdateArtifact("AM_ENGINE_PATCH.exe", `C:\Windows\Prefetch\AM_ENGINE_PATCH.pf`) {
		t.Fatal("expected Defender AM_ENGINE artifact to be benign context")
	}
	if !policyIsOfficialRobloxPath(`C:\Users\Alice\AppData\Local\Roblox\Versions\version-abc\RobloxPlayerBeta.dll`) {
		t.Fatal("expected official Roblox version directory to be recognized")
	}
	if !policyIsCommonWindowsDLL("cfgmgr32.dll", `C:\Windows\System32\cfgmgr32.dll`, "Microsoft Windows", "Microsoft Corporation") {
		t.Fatal("expected common Microsoft DLL to be benign")
	}
}

func TestAF8NormalPersistenceDefaultsAreNotFindings(t *testing.T) {
	if !policyIsNormalPersistenceDefault("winlogon", "Shell", "explorer.exe", "explorer.exe", `HKLM\...\Winlogon`) {
		t.Fatal("expected default Winlogon shell to be benign")
	}
	if !policyIsNormalPersistenceDefault("known_dlls", "kernel32", "kernel32.dll", "kernel32.dll", `HKLM\...\KnownDLLs`) {
		t.Fatal("expected default KnownDLLs value to be benign")
	}
}

func TestAF8WarningRequiresStrongSignals(t *testing.T) {
	if policyShouldCreateFinding("review", "INFO", []string{"historical_artifact_context"}, "") {
		t.Fatal("single historical artifact should not create a warning finding")
	}
	if policyShouldCreateFinding("review", "WARNING", []string{"localappdata_path"}, "") {
		t.Fatal("single LocalAppData signal should not create a warning finding")
	}
	if !policyShouldCreateFinding("review", "WARNING", []string{"localappdata_path", "unsigned_user_writable_path"}, "unsigned") {
		t.Fatal("multi-signal unsigned user-writable artifact should create finding")
	}
}
