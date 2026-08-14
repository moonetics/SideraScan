package windows

import "testing"

func TestMatchBuiltInUtilityDetectsKnownTools(t *testing.T) {
	match := MatchBuiltInUtility("cheatengine-x86_64.exe", `C:\Tools\Cheat Engine\cheatengine-x86_64.exe`)
	if !match.Matched {
		t.Fatal("expected cheat engine to match a built-in utility rule")
	}
	if match.Category != "memory_editor" {
		t.Fatalf("expected memory_editor category, got %q", match.Category)
	}
	if match.Status != "suspicious" {
		t.Fatalf("expected suspicious status, got %q", match.Status)
	}
}

func TestMatchBuiltInUtilityDoesNotFlagNormalProcess(t *testing.T) {
	match := MatchBuiltInUtility("notepad.exe", `C:\Windows\System32\notepad.exe`)
	if match.Matched {
		t.Fatalf("expected notepad to stay unflagged, got %+v", match)
	}
}
