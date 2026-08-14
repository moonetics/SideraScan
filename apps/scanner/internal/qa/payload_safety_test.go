package qa

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

func TestRepresentativeUploadPayloadSchemaAndPrivacy(t *testing.T) {
	now := time.Date(2026, 8, 13, 7, 0, 0, 0, time.UTC)
	request := contract.UploadResultsRequest{
		UploadToken:    "top-level-upload-token",
		Nonce:          "top-level-nonce",
		ScannerVersion: "0.1.0",
		StartedAt:      now.Add(-10 * time.Second).Format(time.RFC3339),
		FinishedAt:     now.Format(time.RFC3339),
		Overview: map[string]any{
			"os":                 "Windows 11",
			"computerStartedAt":  now.Add(-2 * time.Hour).Format(time.RFC3339),
			"connectionType":     "Ethernet",
			"recycleBin":         "Unknown",
			"maskedExamplePath":  `C:\Users\***\Downloads\RobloxTool.exe`,
			"deviceFingerprint":  "dfp_ab12cd34",
			"scannerKeyStatus":   "[REDACTED]",
			"privatePathExample": `C:\Users\***\AppData\Local\Roblox`,
		},
		SystemIdentity: map[string]any{
			"arch":                         "amd64",
			"runAsAdmin":                   false,
			"deviceFingerprintSignalsUsed": []any{"machine_guid_hash", "cpu_name", "gpu_name"},
		},
		NetworkSnapshot: map[string]any{
			"connectionType": "Ethernet",
		},
		Integrity: map[string]any{
			"payloadHash": "abc123",
			"telemetry": map[string]any{
				"uploadRetryCount": 1,
				"lastErrorCode":    "NETWORK_UNAVAILABLE",
			},
		},
		DeviceFingerprint: &contract.DeviceFingerprint{
			Hash:       "dfp_hash_only_value",
			Version:    "siderascan-fp-v1",
			Confidence: "MEDIUM",
		},
		Modules: []contract.ModuleResult{
			{ModuleName: "overview", Status: "completed", DurationMs: 12},
			{ModuleName: "process_timeline", Status: "partial", DurationMs: 25, ErrorCode: "ACCESS_LIMITED", ErrorMessage: "[REDACTED]"},
		},
		ProcessTimeline: []map[string]any{
			{"processName": "RobloxPlayerBeta.exe", "path": `C:\Users\***\AppData\Local\Roblox\RobloxPlayerBeta.exe`, "status": "running"},
		},
		Utilities: []map[string]any{
			{"category": "process_tool", "path": `C:\Users\***\Downloads\tool.exe`, "status": "review"},
		},
		WindowsItems: []map[string]any{
			{"type": "service", "name": "DiagTrack", "status": "observed"},
		},
		LauncherProfiles: []contract.LauncherProfile{
			{ProfileName: "Bloxstrap", LauncherType: "bloxstrap", Path: `C:\Users\***\AppData\Local\Bloxstrap\Bloxstrap.exe`, Status: "customized", Tags: []string{"third_party"}},
		},
		ClientModAssets: []contract.ClientModAsset{
			{Name: "Bloxstrap Modifications", SourceLauncher: "Bloxstrap", Path: `C:\Users\***\AppData\Local\Bloxstrap\Modifications`, FileCount: 2, Status: "customized"},
		},
		ProcessTimes: []contract.ProcessTime{
			{ProcessName: "RobloxPlayerBeta.exe", Path: `C:\Users\***\AppData\Local\Roblox\RobloxPlayerBeta.exe`, Source: "live_process", Status: "running"},
		},
		FileLogs: []contract.FileLog{
			{Action: "downloaded_file", Path: `C:\Users\***\Downloads\RobloxTool.exe`, Source: "downloads_metadata", Confidence: 70, Severity: "INFO"},
		},
		LoadedModules: []map[string]any{
			{"moduleName": "overlay.dll", "path": `C:\Users\***\AppData\Local\Overlay\overlay.dll`, "source": "qa"},
		},
		ProcessHandles: []map[string]any{
			{"sourceProcess": "tool.exe", "targetProcess": "RobloxPlayerBeta.exe", "sourcePath": `C:\Users\***\Downloads\tool.exe`},
		},
		Services: []map[string]any{
			{"name": "ExampleService", "imagePath": `C:\Users\***\AppData\Local\svc.exe`},
		},
		Drivers: []map[string]any{
			{"name": "example.sys", "path": `C:\Windows\System32\drivers\example.sys`},
		},
		PersistenceItems: []map[string]any{
			{"type": "run_key", "path": `C:\Users\***\AppData\Roaming\loader.exe`},
		},
		EventLogs: []map[string]any{
			{"eventId": 7045, "source": "system_event_log"},
		},
		DefenderEvents: []map[string]any{
			{"eventType": "defender_detection", "category": "HackTool"},
		},
		ExecutionArtifacts: []map[string]any{
			{"artifactType": "prefetch", "path": `C:\Users\***\Downloads\tool.exe`},
		},
		FileTriage: []map[string]any{
			{"path": `C:\Users\***\Downloads\tool.exe`, "sha256": "abc123"},
		},
		NetworkConnections: []map[string]any{
			{"processName": "tool.exe", "remoteAddress": "203.0.113.10"},
		},
		DNSCache: []map[string]any{
			{"domain": "example.invalid", "confidence": 20},
		},
		HostsEntries: []map[string]any{
			{"host": "example.invalid", "address": "127.0.0.1"},
		},
		ForensicTimeline: []map[string]any{
			{"timestamp": now.Format(time.RFC3339), "event": "qa_forensic_event"},
		},
		Evidence: []contract.Evidence{
			{
				ClientEvidenceID: "process-1",
				Type:             "process",
				Title:            "QA process evidence",
				Data: map[string]any{
					"path":        `C:\Users\***\Downloads\tool.exe`,
					"commandLine": `C:\Users\***\Downloads\tool.exe --token [REDACTED]`,
				},
			},
		},
		Findings: []contract.Finding{
			{Category: "CUSTOM_DETECTION", Severity: "INFO", Title: "QA finding", Message: "Representative QA finding.", EvidenceRef: "process-1", SourceModule: "qa", Confidence: 100},
		},
		AuditLog: []map[string]any{
			{"action": "payload_hashed", "source": "siderascan_scanner", "createdAt": now.Format(time.RFC3339)},
		},
	}

	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal representative payload: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode representative payload: %v", err)
	}

	for _, key := range []string{
		"uploadToken",
		"nonce",
		"scannerVersion",
		"startedAt",
		"finishedAt",
		"overview",
		"systemIdentity",
		"networkSnapshot",
		"integrity",
		"deviceFingerprint",
		"modules",
		"processTimeline",
		"utilities",
		"windowsItems",
		"launcherProfiles",
		"clientModAssets",
		"processTimes",
		"fileLogs",
		"loadedModules",
		"processHandles",
		"services",
		"drivers",
		"persistenceItems",
		"eventLogs",
		"defenderEvents",
		"executionArtifacts",
		"fileTriage",
		"networkConnections",
		"dnsCache",
		"hostsEntries",
		"forensicTimeline",
		"evidence",
		"findings",
		"auditLog",
	} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("representative payload missing %q", key)
		}
	}

	assertNoForbiddenNestedText(t, decoded, nil)
}

func assertNoForbiddenNestedText(t *testing.T, value any, path []string) {
	t.Helper()

	if len(path) == 1 && (path[0] == "uploadToken" || path[0] == "nonce") {
		return
	}

	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			assertNoForbiddenNestedText(t, item, append(path, key))
		}
	case []any:
		for _, item := range typed {
			assertNoForbiddenNestedText(t, item, append(path, "[]"))
		}
	case string:
		lower := strings.ToLower(typed)
		for _, forbidden := range []string{
			"top-level-upload-token",
			"top-level-nonce",
			"sds_live_",
			"raw-guid",
			"raw-serial",
			"machineguid:",
			"serialnumber:",
			"password=",
			"cookie=",
			"clipboard:",
			"screenshot:",
			`c:\users\alice`,
			`c:/users/alice`,
			"/users/alice",
		} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("payload leaked forbidden value %q at %s: %q", forbidden, strings.Join(path, "."), typed)
			}
		}
	}
}
