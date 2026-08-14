//go:build windows

package windows

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gopsnet "github.com/shirou/gopsutil/v4/net"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

func TestHashExecutableIfAllowedHashesSmallMatchedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "matched.exe")
	if err := os.WriteFile(path, []byte("safe test fixture"), 0o600); err != nil {
		t.Fatal(err)
	}

	hash, status := hashExecutableIfAllowed(path)
	if status != "hashed" {
		t.Fatalf("expected hashed status, got %q", status)
	}
	if len(hash) != 64 {
		t.Fatalf("expected sha256 hex hash, got %q", hash)
	}
}

func TestHashExecutableIfAllowedSkipsLargeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.exe")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(MaxExecutableHashMB+1) * 1024 * 1024); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	hash, status := hashExecutableIfAllowed(path)
	if status != "file_too_large" {
		t.Fatalf("expected file_too_large status, got %q", status)
	}
	if hash != "" {
		t.Fatalf("expected no hash for large file, got %q", hash)
	}
}

func TestRedactCommandLineMasksPathsAndSecrets(t *testing.T) {
	input := `C:\Users\Alice\AppData\Local\Roblox\RobloxPlayerBeta.exe --token secret-value --password=hunter2 https://example.invalid/?cookie=abc`
	output := redactCommandLine(input)

	for _, forbidden := range []string{"Alice", "secret-value", "hunter2", "cookie=abc"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("command line leaked %q in %q", forbidden, output)
		}
	}
	for _, expected := range []string{`C:\Users\***`, "[REDACTED]"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("command line missing %q in %q", expected, output)
		}
	}
}

func TestSuspiciousPathFlagsDetectUserWritableSpoof(t *testing.T) {
	flags := suspiciousPathFlags(
		"svchost.exe",
		`C:\Users\Alice\AppData\Local\Temp\svchost.exe`,
		signatureInfo{Status: "unsigned"},
	)

	for _, expected := range []string{
		"temp_path",
		"localappdata_path",
		"windows_like_name_outside_windows",
		"unsigned_user_writable_path",
	} {
		if !containsString(flags, expected) {
			t.Fatalf("expected flag %q in %#v", expected, flags)
		}
	}
}

func TestClassifyProcessStatusDoesNotMarkBestEffortLimitedAsLimited(t *testing.T) {
	status := classifyProcessStatus(false, nil, RuleMatch{})
	if status != "running" {
		t.Fatalf("expected running for core data available, got %q", status)
	}

	status = classifyProcessStatus(true, nil, RuleMatch{})
	if status != "limited" {
		t.Fatalf("expected limited for core data unavailable, got %q", status)
	}
}

func TestSuspiciousProcessEvidenceUsesEvidenceRef(t *testing.T) {
	row := map[string]any{
		"processName":      "svchost.exe",
		"pid":              int32(123),
		"path":             `C:\Users\***\AppData\Local\Temp\svchost.exe`,
		"signatureStatus":  "unsigned",
		"suspiciousFlags":  []string{"unsigned_user_writable_path"},
		"executableSha256": strings.Repeat("a", 64),
	}
	evidence, finding := buildSuspiciousProcessEvidence(row, "svchost.exe", 123, []string{"unsigned_user_writable_path"}, "WARNING", 90)

	if evidence.ClientEvidenceID == "" {
		t.Fatal("expected client evidence id")
	}
	if finding.EvidenceRef != evidence.ClientEvidenceID {
		t.Fatalf("expected finding evidence ref %q, got %q", evidence.ClientEvidenceID, finding.EvidenceRef)
	}
	if finding.Category != "PROCESS" || finding.SourceModule != "process_timeline" {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}

func TestSelectForensicTargetsIncludesRobloxAndProcessRule(t *testing.T) {
	targets := selectForensicTargets([]map[string]any{
		{"processName": "RobloxPlayerBeta.exe", "pid": int32(10), "path": `C:\Users\***\AppData\Local\Roblox\RobloxPlayerBeta.exe`},
		{"processName": "safe.exe", "pid": int32(11), "path": `C:\Program Files\Safe\safe.exe`},
		{"processName": "CustomGame.exe", "pid": int32(12), "path": `C:\Games\CustomGame.exe`},
	}, []contract.ScannerRule{
		{
			ID:       "rule_process_custom_game",
			Name:     "Custom game",
			Type:     "PROCESS_NAME",
			Category: "PROCESS",
			Severity: "WARNING",
			RuleConfig: map[string]any{
				"processNames": []any{"CustomGame.exe"},
				"matchMode":    "exact",
			},
		},
	})

	if len(targets) != 2 {
		t.Fatalf("expected 2 forensic targets, got %#v", targets)
	}
	if targets[0].Source != "default_roblox_target" || targets[1].Source != "custom_process_rule_target" {
		t.Fatalf("unexpected target sources: %#v", targets)
	}
}

func TestOverlayAllowlistKeepsSeverityInformational(t *testing.T) {
	record := loadedModuleRecord{
		Target:      forensicTarget{ProcessName: "RobloxPlayerBeta.exe", PID: 10, Source: "default_roblox_target"},
		ModuleName:  "DiscordHook64.dll",
		RawPath:     `C:\Users\Alice\AppData\Roaming\Discord\DiscordHook64.dll`,
		BaseAddress: "0x1000",
	}
	row, evidence, finding := loadedModuleRow(context.Background(), record, MaxExecutableHashMB, map[string]signatureInfo{
		record.RawPath: {Status: "unsigned", Publisher: "Discord"},
	})

	if row["severity"] != "INFO" {
		t.Fatalf("expected legit overlay severity INFO, got %#v", row)
	}
	if evidence != nil || finding != nil {
		t.Fatalf("expected no automatic finding for legit overlay, got evidence=%#v finding=%#v", evidence, finding)
	}
}

func TestDecodeProcessAccessFlagsSensitiveRights(t *testing.T) {
	rights := decodeProcessAccess(0x0010 | 0x0020 | 0x1000)
	for _, expected := range []string{"vm_read", "vm_write", "query_limited_information"} {
		if !containsString(rights, expected) {
			t.Fatalf("expected access right %q in %#v", expected, rights)
		}
	}
	if !hasSensitiveProcessAccess(rights) {
		t.Fatalf("expected sensitive process access for %#v", rights)
	}
}

func TestLoadedModuleFindingEvidenceRefAndRedaction(t *testing.T) {
	record := loadedModuleRecord{
		Target:      forensicTarget{ProcessName: "RobloxPlayerBeta.exe", PID: 10, Source: "default_roblox_target"},
		ModuleName:  "a9f81c2d.dll",
		RawPath:     `C:\Users\Alice\AppData\Local\Temp\a9f81c2d.dll`,
		BaseAddress: "0x1000",
	}
	row, evidence, finding := loadedModuleRow(context.Background(), record, MaxExecutableHashMB, map[string]signatureInfo{
		record.RawPath: {Status: "unsigned"},
	})

	if evidence == nil || finding == nil {
		t.Fatalf("expected suspicious loaded module evidence/finding, row=%#v", row)
	}
	if finding.EvidenceRef != evidence.ClientEvidenceID {
		t.Fatalf("expected evidence ref %q, got %q", evidence.ClientEvidenceID, finding.EvidenceRef)
	}
	raw, err := json.Marshal([]any{row, evidence, finding})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(raw)), `c:\users\alice`) {
		t.Fatalf("AF-2 payload leaked private user path: %s", raw)
	}
}

func TestAF3ReviewModeFiltersNormalRows(t *testing.T) {
	rows := []map[string]any{
		{"name": "safe-service", "status": "normal"},
		{"name": "review-task", "status": "review"},
		{"name": "missing-driver", "status": "missing_file"},
	}

	relevant := filterAF3Rows(rows, "review_relevant_only", 10)
	if len(relevant) != 2 {
		t.Fatalf("expected only review-relevant rows, got %#v", relevant)
	}

	full := filterAF3Rows(rows, "ai_assisted_full", 10)
	if len(full) != 3 {
		t.Fatalf("expected full rows for AI-assisted mode, got %#v", full)
	}
}

func TestAF3RowMasksCommandAndCreatesMissingFileFinding(t *testing.T) {
	item := forensicItem{
		Module:   "persistence",
		Kind:     "scheduled_task",
		Name:     "Windows Update Service",
		Path:     `C:\Users\Alice\AppData\Local\Temp\missing-task.exe`,
		Command:  `powershell.exe -NoProfile -File C:\Users\Alice\AppData\Local\Temp\missing-task.ps1 -token secret-value`,
		Location: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		Source:   "test_fixture",
	}
	row := af3Row(context.Background(), item, MaxExecutableHashMB, map[string]signatureInfo{
		item.Path: {Status: "unsigned"},
	})

	if row["status"] != "missing_file" {
		t.Fatalf("expected missing_file status, got %#v", row["status"])
	}
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	payload := string(raw)
	for _, forbidden := range []string{"Alice", "secret-value"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("AF-3 row leaked %q in %s", forbidden, payload)
		}
	}
	if !strings.Contains(payload, `C:\\Users\\***`) {
		t.Fatalf("expected masked private path in %s", payload)
	}

	evidence, finding := buildAF3EvidenceFinding(row)
	if finding.EvidenceRef != evidence.ClientEvidenceID {
		t.Fatalf("expected evidence ref %q, got %q", evidence.ClientEvidenceID, finding.EvidenceRef)
	}
}

func TestAF3DriverPathFlagsOutsideSystem32(t *testing.T) {
	t.Setenv("WINDIR", `C:\Windows`)

	if !driverOutsideSystem32(`C:\Users\Alice\AppData\Local\Temp\bad.sys`) {
		t.Fatal("expected user temp driver to be outside System32 drivers")
	}
	if driverOutsideSystem32(`C:\Windows\System32\drivers\good.sys`) {
		t.Fatal("expected System32 drivers path to be allowed")
	}
}

func TestAF3ScheduledTaskCommandExtractsExecutableAndRedactsSecrets(t *testing.T) {
	command := `"C:\Users\Alice\AppData\Local\Temp\runme.exe" --password hunter2`
	executable := executableFromCommand(command)
	if executable != `C:\Users\Alice\AppData\Local\Temp\runme.exe` {
		t.Fatalf("unexpected executable extraction: %q", executable)
	}

	redacted := redactCommandLine(command)
	if strings.Contains(redacted, "Alice") || strings.Contains(redacted, "hunter2") {
		t.Fatalf("command redaction leaked private data: %q", redacted)
	}
}

func TestAF4ParseEventRowsAndDropsRawXMLSummary(t *testing.T) {
	rows, err := parsePowerShellEventRows([]byte(`[{"logName":"Security","provider":"Microsoft-Windows-Security-Auditing","eventId":1102,"recordId":42,"timestamp":"2026-08-13T01:00:00Z","level":"Information","properties":["Alice","<Event><Secret>raw</Secret></Event>","C:\\Users\\Alice\\Temp\\tool.exe"]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].EventID != 1102 {
		t.Fatalf("unexpected parsed rows: %#v", rows)
	}

	summary := safePropertySummary(rows[0].Properties, 8)
	raw, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "<Event>") || strings.Contains(string(raw), `C:\\Users\\Alice`) {
		t.Fatalf("raw XML or private user leaked in summary: %s", raw)
	}
}

func TestAF4EventLogClearedCreatesSevereFinding(t *testing.T) {
	row := windowsEventRow(psEventRow{
		LogName:   "Security",
		Provider:  "Microsoft-Windows-Security-Auditing",
		EventID:   1102,
		Timestamp: "2026-08-13T01:00:00Z",
	}, "windows_security_event_log")

	if row["severity"] != "SEVERE" {
		t.Fatalf("expected severe event-log-cleared row, got %#v", row)
	}
	evidence, finding := buildAF4EvidenceFinding(row)
	if finding.EvidenceRef != evidence.ClientEvidenceID {
		t.Fatalf("expected evidence ref %q, got %q", evidence.ClientEvidenceID, finding.EvidenceRef)
	}
	if finding.Severity != "SEVERE" || finding.Category != "WINDOWS_ITEM" {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}

func TestAF4DefenderExclusionMasksPathAndFlagsSuspicious(t *testing.T) {
	rows := defenderExclusionRows("path", []any{`C:\Users\Alice\AppData\Local\Temp`})
	if len(rows) != 1 {
		t.Fatalf("expected one exclusion row, got %#v", rows)
	}
	raw, err := json.Marshal(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	payload := string(raw)
	if strings.Contains(payload, "Alice") {
		t.Fatalf("defender exclusion leaked private path: %s", payload)
	}
	if rows[0]["status"] != "review" {
		t.Fatalf("expected review status for user-writable exclusion, got %#v", rows[0])
	}
}

func TestAF4ReviewModeFiltersNormalRows(t *testing.T) {
	rows := []map[string]any{
		{"title": "Defender status", "status": "normal"},
		{"title": "Defender exclusion", "status": "review"},
	}
	relevant := filterAF4Rows(rows, "review_relevant_only", 10)
	if len(relevant) != 1 {
		t.Fatalf("expected one review-relevant row, got %#v", relevant)
	}
	full := filterAF4Rows(rows, "ai_assisted_full", 10)
	if len(full) != 2 {
		t.Fatalf("expected full rows in AI mode, got %#v", full)
	}
}

func TestAF5PrefetchNameParsing(t *testing.T) {
	got := relatedProcessFromPrefetchName("ROBLOXPLAYERBETA.EXE-12345678.pf")
	if got != "ROBLOXPLAYERBETA.EXE" {
		t.Fatalf("unexpected prefetch related process: %q", got)
	}
	got = relatedProcessFromPrefetchName("ABCDEF12-12345678.pf")
	if got != "ABCDEF12.exe" {
		t.Fatalf("expected exe suffix for bare prefetch name, got %q", got)
	}
}

func TestAF5DirectoryTraversalIsCappedAndMasked(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tool.exe"), []byte("not uploaded"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "skip.exe"), []byte("not uploaded"), 0o600); err != nil {
		t.Fatal(err)
	}

	rows, logs, err := collectAF5DirectoryEntries(root, "downloads_metadata", "downloaded_file", "test_source", suspiciousArtifactExtensions(), 60, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || len(logs) != 1 {
		t.Fatalf("expected direct file only, rows=%#v logs=%#v", rows, logs)
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "not uploaded") {
		t.Fatalf("AF-5 uploaded file content: %s", raw)
	}
}

func TestAF5PowerShellHistoryRedactionAndFlags(t *testing.T) {
	command := `powershell.exe -EncodedCommand ZQB2AGkAbA== -File C:\Users\Alice\Downloads\run.ps1 --token secret`
	if !isRelevantPowerShellHistory(command) {
		t.Fatal("expected command to be relevant")
	}
	flags := powerShellHistoryFlags(command)
	if !containsString(flags, "powershell_encoded_command") {
		t.Fatalf("expected encoded command flag in %#v", flags)
	}
	redacted := redactCommandLine(command)
	if strings.Contains(redacted, "Alice") || strings.Contains(redacted, "secret") {
		t.Fatalf("PowerShell command leaked private data: %q", redacted)
	}
}

func TestAF5ReviewModeFiltersNormalRows(t *testing.T) {
	rows := []map[string]any{
		{"name": "Amcache.hve", "status": "normal"},
		{"name": "run.ps1", "status": "review"},
	}
	relevant := filterAF5Rows(rows, "review_relevant_only", 10)
	if len(relevant) != 1 {
		t.Fatalf("expected one review-relevant row, got %#v", relevant)
	}
	full := filterAF5Rows(rows, "ai_assisted_full", 10)
	if len(full) != 2 {
		t.Fatalf("expected full rows in AI mode, got %#v", full)
	}
}

func TestAF5FindingEvidenceRefAndSafety(t *testing.T) {
	row := executionArtifactRow(af5Artifact{
		ArtifactType: "temp_metadata",
		Action:       "data_change",
		Name:         "svchost.exe",
		Path:         `C:\Users\Alice\AppData\Local\Temp\svchost.exe`,
		Source:       "test_source",
		Confidence:   80,
		Status:       "suspicious",
		Severity:     "WARNING",
		Flags:        []string{"windows_like_name_outside_windows"},
		Metadata:     map[string]any{"content": "metadata only"},
	})
	evidence, finding := buildAF5EvidenceFinding(row)
	if finding.EvidenceRef != evidence.ClientEvidenceID {
		t.Fatalf("expected evidence ref %q, got %q", evidence.ClientEvidenceID, finding.EvidenceRef)
	}
	raw, err := json.Marshal([]any{row, evidence, finding})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "Alice") {
		t.Fatalf("AF-5 payload leaked private path: %s", raw)
	}
}

func TestAF6TriageKeepsMaskedArtifactAndDoesNotHashIt(t *testing.T) {
	rows := buildFileTriageRows(context.Background(), []triageCandidate{
		{
			Path:           `C:\Users\***\AppData\Local\Temp\svchost.exe`,
			Name:           "svchost.exe",
			SourceArtifact: "process_timeline",
			ReasonFlags:    []string{"windows_like_name_outside_windows"},
			MaskedPathOnly: true,
		},
	}, MaxExecutableHashMB, map[string]signatureInfo{}, 10)

	if len(rows) != 1 {
		t.Fatalf("expected one triage row, got %#v", rows)
	}
	if rows[0]["hashStatus"] != "not_checked_masked_path" {
		t.Fatalf("expected masked path hash skip, got %#v", rows[0]["hashStatus"])
	}
	ads, ok := rows[0]["ads"].(map[string]any)
	if !ok || ads["contentRead"] != false {
		t.Fatalf("expected ADS metadata without content read, got %#v", rows[0]["ads"])
	}
	raw, err := json.Marshal(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "Alice") {
		t.Fatalf("AF-6 masked row leaked private user: %s", raw)
	}
}

func TestAF6DNSAndHostsRelevantOnly(t *testing.T) {
	if !isRelevantDNSDomain("cdn.discordapp.com") || !isRelevantDNSDomain("roblox.com") {
		t.Fatal("expected Roblox/Discord domains to be relevant")
	}
	if isRelevantDNSDomain("example.com") {
		t.Fatal("expected generic domain to be ignored")
	}

	flags := hostsReasonFlags("0.0.0.0", "clientsettingscdn.roblox.com")
	if !containsString(flags, "hosts_blocks_roblox") {
		t.Fatalf("expected Roblox hosts block flag, got %#v", flags)
	}
	if isSuspiciousHostEntry("8.8.8.8", "example.com") {
		t.Fatal("expected unrelated hosts entry to be ignored")
	}
}

func TestAF6NetworkContextFlagsPublicRemoteForReviewProcess(t *testing.T) {
	process := map[string]any{
		"processName":     "svchost.exe",
		"status":          "review",
		"suspiciousFlags": []string{"windows_like_name_outside_windows"},
	}
	flags := networkReasonFlags(gopsnet.ConnectionStat{
		Raddr: gopsnet.Addr{IP: "8.8.8.8", Port: 4444},
	}, process)

	for _, expected := range []string{"remote_public_connection", "suspicious_process_network_activity", "interesting_remote_port"} {
		if !containsString(flags, expected) {
			t.Fatalf("expected network flag %q in %#v", expected, flags)
		}
	}
	if !isPrivateOrLoopbackIP("127.0.0.1") || !isPrivateOrLoopbackIP("192.168.1.10") {
		t.Fatal("expected loopback/private IP to be recognized")
	}
}

func TestAF6FindingEvidenceRefAndSafety(t *testing.T) {
	row := map[string]any{
		"fileName":    "svchost.exe",
		"path":        `C:\Users\***\AppData\Local\Temp\svchost.exe`,
		"status":      "suspicious",
		"severity":    "WARNING",
		"confidence":  84,
		"source":      "af6_file_triage",
		"reasonFlags": []string{"windows_like_name_outside_windows"},
	}
	evidence, finding := buildAF6EvidenceFinding(row)
	if finding.EvidenceRef != evidence.ClientEvidenceID {
		t.Fatalf("expected evidence ref %q, got %q", evidence.ClientEvidenceID, finding.EvidenceRef)
	}
	raw, err := json.Marshal([]any{row, evidence, finding})
	if err != nil {
		t.Fatal(err)
	}
	payload := string(raw)
	for _, forbidden := range []string{"Alice", "scannerKey", "uploadToken", "nonce", "MachineGuid", "serial"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("AF-6 finding leaked %q in %s", forbidden, payload)
		}
	}
}

func TestAF7TimelineSortsUnknownTimestampsLast(t *testing.T) {
	snapshot := BaselineSnapshot{
		ProcessTimeline: []map[string]any{
			{"processName": "late.exe", "startedAt": "2026-08-13T02:00:00Z", "status": "running"},
			{"processName": "unknown.exe", "status": "running"},
			{"processName": "early.exe", "startedAt": "2026-08-13T01:00:00Z", "status": "running"},
		},
	}

	entries := buildForensicTimelineEntries(snapshot)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %#v", entries)
	}
	if entries[0].ProcessName != "early.exe" || entries[1].ProcessName != "late.exe" || entries[2].ProcessName != "unknown.exe" {
		t.Fatalf("timeline did not sort timestamps with unknown last: %#v", entries)
	}
	if entries[2].TimestampConfidence != "unknown" {
		t.Fatalf("expected unknown timestamp confidence, got %#v", entries[2])
	}
}

func TestAF7CorrelationRequiresMultiSignal(t *testing.T) {
	snapshot := BaselineSnapshot{
		ProcessTimeline: []map[string]any{
			{"processName": "RobloxPlayerBeta.exe", "startedAt": "2026-08-13T01:00:00Z", "status": "running"},
			{
				"processName":     "svchost.exe",
				"path":            `C:\Users\***\AppData\Local\Temp\svchost.exe`,
				"startedAt":       "2026-08-13T01:05:00Z",
				"status":          "suspicious",
				"severity":        "WARNING",
				"suspiciousFlags": []string{"temp_path", "windows_like_name_outside_windows"},
				"signatureStatus": "unsigned",
				"confidence":      90,
			},
			{
				"processName":     "loader.exe",
				"startedAt":       "2026-08-13T01:06:00Z",
				"status":          "review",
				"severity":        "WARNING",
				"suspiciousFlags": []string{"loader_name_only"},
				"confidence":      50,
			},
		},
	}

	result := collectForensicTimelineCorrelation(snapshot, BaselineOptions{})
	if len(result.Findings) == 0 {
		t.Fatal("expected multi-signal process correlation finding")
	}
	for _, finding := range result.Findings {
		if finding.EvidenceRef == "" {
			t.Fatalf("expected evidence ref on correlated finding: %#v", finding)
		}
		if finding.Category != "INTEGRITY" || finding.SourceModule != "forensic_correlation" {
			t.Fatalf("unexpected correlation finding category/source: %#v", finding)
		}
	}
}

func TestAF7SingleDNSOrUSBContextDoesNotCreateSevereFinding(t *testing.T) {
	snapshot := BaselineSnapshot{
		DNSCache: []map[string]any{
			{"domain": "roblox.com", "status": "context", "severity": "INFO", "reasonFlags": []string{"dns_roblox"}},
		},
		NetworkConnections: []map[string]any{
			{"forensicSource": "usb_history", "deviceLabel": "USB Mass Storage", "status": "context", "severity": "INFO", "reasonFlags": []string{"usb_history_context"}},
		},
	}

	result := collectForensicTimelineCorrelation(snapshot, BaselineOptions{})
	for _, finding := range result.Findings {
		if finding.Severity == "SEVERE" {
			t.Fatalf("DNS/USB single context should not create severe finding: %#v", finding)
		}
	}
}

func TestAF7ArtifactChainCreatesCorrelationEvidence(t *testing.T) {
	snapshot := BaselineSnapshot{
		FileLogs: []contract.FileLog{
			{Action: "downloaded_file", Path: `C:\Users\***\Downloads\tool.exe`, Timestamp: "2026-08-13T01:00:00Z", Severity: "WARNING", Confidence: 70, Source: "test"},
			{Action: "executed_file", Path: `C:\Users\***\Downloads\tool.exe`, Timestamp: "2026-08-13T01:10:00Z", Severity: "WARNING", Confidence: 80, Source: "test"},
			{Action: "deleted_file", Path: `C:\Users\***\Downloads\tool.exe`, Timestamp: "2026-08-13T01:20:00Z", Severity: "WARNING", Confidence: 80, Source: "test"},
		},
	}

	result := collectForensicTimelineCorrelation(snapshot, BaselineOptions{})
	if len(result.Findings) == 0 || len(result.Evidence) == 0 {
		t.Fatalf("expected chain correlation evidence/finding, result=%#v", result)
	}
	found := false
	for _, finding := range result.Findings {
		if strings.Contains(strings.ToLower(finding.Title), "downloaded/executed/deleted") {
			found = true
			if finding.EvidenceRef == "" {
				t.Fatal("expected evidence ref for artifact chain finding")
			}
		}
	}
	if !found {
		t.Fatalf("expected artifact chain correlation finding, got %#v", result.Findings)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"Alice", "scannerKey", "uploadToken", "nonce", "MachineGuid", "serial", "cookie", "clipboard"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("AF-7 payload leaked %q in %s", forbidden, raw)
		}
	}
}
