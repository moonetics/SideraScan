package privacy

import "testing"

func TestMaskPathMasksWindowsAndUnixUsers(t *testing.T) {
	tests := map[string]string{
		`C:\Users\Alice\Downloads\tool.exe`: `C:\Users\***\Downloads\tool.exe`,
		`C:/Users/Bob/AppData/Local`:        `C:/Users/***/AppData/Local`,
		`/Users/charlie/Desktop/file`:       `/Users/***/Desktop/file`,
	}

	for input, want := range tests {
		if got := MaskPath(input); got != want {
			t.Fatalf("MaskPath(%q)=%q want %q", input, got, want)
		}
	}
}

func TestRedactMapRedactsSensitiveKeys(t *testing.T) {
	clean := RedactMap(map[string]any{
		"machineGuid":  "raw-guid",
		"serialNumber": "raw-serial",
		"safePath":     `C:\Users\Alice\Downloads\tool.exe`,
		"nested": map[string]any{
			"uploadToken": "secret",
		},
	})

	if clean["machineGuid"] != "[REDACTED]" {
		t.Fatalf("machine guid leaked: %#v", clean)
	}
	if clean["serialNumber"] != "[REDACTED]" {
		t.Fatalf("serial leaked: %#v", clean)
	}
	if clean["safePath"] != `C:\Users\***\Downloads\tool.exe` {
		t.Fatalf("path was not masked: %#v", clean["safePath"])
	}
	nested := clean["nested"].(map[string]any)
	if nested["uploadToken"] != "[REDACTED]" {
		t.Fatalf("nested token leaked: %#v", nested)
	}
}

func TestRedactValueRecursesThroughArrays(t *testing.T) {
	clean := RedactValue([]any{
		map[string]any{
			"path":         `C:\Users\Alice\Downloads\tool.exe`,
			"machine_guid": "raw-guid",
		},
		"clipboard: secret",
		[]any{
			map[string]any{
				"cookieValue": "session-cookie",
			},
		},
	}).([]any)

	first := clean[0].(map[string]any)
	if first["path"] != `C:\Users\***\Downloads\tool.exe` {
		t.Fatalf("array path was not masked: %#v", first["path"])
	}
	if first["machine_guid"] != "[REDACTED]" {
		t.Fatalf("array nested machine guid leaked: %#v", first)
	}
	if clean[1] != "[REDACTED]" {
		t.Fatalf("array string sensitive value leaked: %#v", clean[1])
	}
	nested := clean[2].([]any)[0].(map[string]any)
	if nested["cookieValue"] != "[REDACTED]" {
		t.Fatalf("array nested cookie leaked: %#v", nested)
	}
}
