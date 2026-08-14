//go:build windows

package windows

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/StackExchange/wmi"
	gopsprocess "github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/windows/registry"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
	"github.com/moonetics/SideraScan/apps/scanner/internal/privacy"
)

type win32Service struct {
	Name        string
	DisplayName string
	State       string
	StartMode   string
	PathName    string
}

func collectBaseline(ctx context.Context, options BaselineOptions) BaselineSnapshot {
	snapshot := BaselineSnapshot{}
	partials := []string{}
	warnings := []string{}
	signatureCache := map[string]signatureInfo{}

	processTimeline, utilities, evidence, findings, stringCandidates, err := collectProcessTimeline(ctx, signatureCache)
	if err != nil {
		if len(processTimeline) == 0 {
			partials = append(partials, "process_timeline")
		} else {
			warnings = append(warnings, err.Error())
		}
	}
	snapshot.ProcessTimeline = processTimeline
	snapshot.Utilities = utilities
	snapshot.Evidence = evidence
	snapshot.Findings = findings
	snapshot.StringCandidateFiles = stringCandidates

	af2 := collectGameProcessForensics(ctx, processTimeline, options, signatureCache)
	snapshot.LoadedModules = af2.LoadedModules
	snapshot.ProcessHandles = af2.ProcessHandles
	snapshot.Evidence = append(snapshot.Evidence, af2.Evidence...)
	snapshot.Findings = append(snapshot.Findings, af2.Findings...)
	warnings = append(warnings, af2.Warnings...)

	af3 := collectServiceDriverPersistenceForensics(ctx, options, signatureCache)
	snapshot.Services = af3.Services
	snapshot.Drivers = af3.Drivers
	snapshot.PersistenceItems = af3.PersistenceItems
	snapshot.AF3Summary = af3.Summary
	snapshot.Evidence = append(snapshot.Evidence, af3.Evidence...)
	snapshot.Findings = append(snapshot.Findings, af3.Findings...)
	warnings = append(warnings, af3.Warnings...)

	af4 := collectEventDefenderForensics(ctx, options)
	snapshot.EventLogs = af4.EventLogs
	snapshot.DefenderEvents = af4.DefenderEvents
	snapshot.AF4Summary = af4.Summary
	snapshot.Evidence = append(snapshot.Evidence, af4.Evidence...)
	snapshot.Findings = append(snapshot.Findings, af4.Findings...)
	warnings = append(warnings, af4.Warnings...)

	af5 := collectExecutionArtifacts(ctx, options)
	snapshot.ExecutionArtifacts = af5.ExecutionArtifacts
	snapshot.FileLogs = af5.FileLogs
	snapshot.AF5Summary = af5.Summary
	snapshot.Evidence = append(snapshot.Evidence, af5.Evidence...)
	snapshot.Findings = append(snapshot.Findings, af5.Findings...)
	warnings = append(warnings, af5.Warnings...)

	af6 := collectFileNetworkForensics(ctx, snapshot, options, signatureCache)
	snapshot.FileTriage = af6.FileTriage
	snapshot.NetworkConnections = af6.NetworkConnections
	snapshot.DNSCache = af6.DNSCache
	snapshot.HostsEntries = af6.HostsEntries
	snapshot.AF6Summary = af6.Summary
	snapshot.Evidence = append(snapshot.Evidence, af6.Evidence...)
	snapshot.Findings = append(snapshot.Findings, af6.Findings...)
	warnings = append(warnings, af6.Warnings...)

	windowsItems, itemWarnings := collectWindowsItems(ctx)
	warnings = append(warnings, itemWarnings...)
	snapshot.WindowsItems = windowsItems

	af7 := collectForensicTimelineCorrelation(snapshot, options)
	snapshot.ForensicTimeline = af7.Timeline
	snapshot.AF7Summary = af7.Summary
	snapshot.Evidence = append(snapshot.Evidence, af7.Evidence...)
	snapshot.Findings = append(snapshot.Findings, af7.Findings...)
	warnings = append(warnings, af7.Warnings...)

	snapshot.PartialErrors = append(snapshot.PartialErrors, partials...)
	snapshot.WarningKeys = append(snapshot.WarningKeys, warnings...)

	return snapshot
}

func collectProcessTimeline(ctx context.Context, signatureCache map[string]signatureInfo) ([]map[string]any, []map[string]any, []contract.Evidence, []contract.Finding, []string, error) {
	processes, err := gopsprocess.ProcessesWithContext(ctx)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	rows := make([]map[string]any, 0, minInt(len(processes), MaxProcessRows))
	utilities := []map[string]any{}
	evidence := []contract.Evidence{}
	findings := []contract.Finding{}
	stringCandidates := []string{}
	networkSummaries := collectNetworkSummaries(ctx)
	partials := 0

	for index, proc := range processes {
		if index >= MaxProcessRows {
			break
		}

		intel := processRow(ctx, proc, networkSummaries, signatureCache)
		if intel.limited {
			partials++
		}
		rows = append(rows, intel.row)
		if intel.evidence != nil {
			evidence = append(evidence, *intel.evidence)
		}
		if intel.finding != nil {
			findings = append(findings, *intel.finding)
		}

		name, _ := intel.row["processName"].(string)
		match := MatchBuiltInUtility(name, intel.rawPath)
		if match.Matched {
			utility := map[string]any{
				"category":       match.Category,
				"status":         match.Status,
				"severity":       match.Severity,
				"confidence":     match.Confidence,
				"matchedRule":    match.RuleID,
				"processName":    name,
				"pid":            intel.row["pid"],
				"path":           privacy.MaskPath(intel.rawPath),
				"source":         "builtin_process_rule",
				"detectedAt":     time.Now().UTC().Format(time.RFC3339),
				"hashPolicy":     "matched_process_only",
				"maxHashFileMB":  MaxExecutableHashMB,
				"relatedProcess": name,
			}
			if executableHash, hashStatus := hashExecutableIfAllowed(intel.rawPath); hashStatus != "" {
				utility["hashStatus"] = hashStatus
				if executableHash != "" {
					utility["executableSha256"] = executableHash
				}
			}
			utilities = append(utilities, privacy.RedactMap(utility))
			if strings.TrimSpace(intel.rawPath) != "" {
				stringCandidates = append(stringCandidates, intel.rawPath)
			}
		}
		if intel.stringCandidate && strings.TrimSpace(intel.rawPath) != "" {
			stringCandidates = append(stringCandidates, intel.rawPath)
		}
	}

	if partials > 0 {
		return rows, utilities, evidence, findings, uniqueStringsSorted(stringCandidates), fmt.Errorf("limited_process_rows:%d", partials)
	}

	return rows, utilities, evidence, findings, uniqueStringsSorted(stringCandidates), nil
}

func processRow(ctx context.Context, proc *gopsprocess.Process, networkSummaries map[int32]map[string]any, signatureCache map[string]signatureInfo) processIntelligence {
	limitedReasons := []string{}
	name, err := proc.NameWithContext(ctx)
	if err != nil {
		name = "Unknown"
		limitedReasons = append(limitedReasons, "process_name_unavailable")
	}

	rawPath, err := proc.ExeWithContext(ctx)
	if err != nil {
		rawPath = ""
		limitedReasons = append(limitedReasons, "path_unavailable")
	}

	parentPID, err := proc.PpidWithContext(ctx)
	if err != nil {
		parentPID = 0
		limitedReasons = append(limitedReasons, "parent_pid_unavailable")
	}
	parentName := ""
	if parentPID > 0 {
		if parent, err := gopsprocess.NewProcessWithContext(ctx, parentPID); err == nil {
			if value, err := parent.NameWithContext(ctx); err == nil {
				parentName = value
			}
		}
	}
	if parentPID > 0 && parentName == "" {
		limitedReasons = append(limitedReasons, "parent_name_unavailable")
	}

	startTime := ""
	if createdMs, err := proc.CreateTimeWithContext(ctx); err == nil && createdMs > 0 {
		startTime = time.UnixMilli(createdMs).UTC().Format(time.RFC3339)
	} else {
		limitedReasons = append(limitedReasons, "start_time_unavailable")
	}

	commandLine := ""
	if value, err := proc.CmdlineWithContext(ctx); err == nil {
		commandLine = redactCommandLine(value)
	} else {
		limitedReasons = append(limitedReasons, "command_line_unavailable")
	}

	owner := ""
	if value, err := proc.UsernameWithContext(ctx); err == nil {
		owner = privacy.RedactString(value)
	} else {
		limitedReasons = append(limitedReasons, "owner_unavailable")
	}

	cwd := ""
	if value, err := proc.CwdWithContext(ctx); err == nil && strings.TrimSpace(value) != "" {
		cwd = privacy.MaskPath(value)
	} else {
		limitedReasons = append(limitedReasons, "cwd_unavailable")
	}

	sessionID := any("Unknown")
	if value, ok := processSessionID(proc.Pid); ok {
		sessionID = value
	} else {
		limitedReasons = append(limitedReasons, "session_id_unavailable")
	}

	match := MatchBuiltInUtility(name, rawPath)
	signature := signatureInfo{Status: "not_checked"}
	preFlags := suspiciousPathFlags(name, rawPath, signature)
	if shouldCheckSignature(rawPath, preFlags, match) && len(signatureCache) < maxSignatureChecksPerScan {
		if cached, ok := signatureCache[rawPath]; ok {
			signature = cached
		} else {
			signature = collectSignatureInfo(ctx, rawPath)
			signatureCache[rawPath] = signature
		}
		if signature.Reason != "" {
			limitedReasons = append(limitedReasons, signature.Reason)
		}
	}

	flags := suspiciousPathFlags(name, rawPath, signature)
	coreLimited := name == "Unknown" && strings.TrimSpace(rawPath) == ""
	status := classifyProcessStatus(coreLimited, flags, match)
	if !match.Matched && policyIsKnownVendorArtifact(name, rawPath, signature.Publisher, signature.Signer) {
		status = "running"
		flags = uniqueStringsSorted(append(flags, "benign_known_vendor_process"))
	}
	confidence := confidenceForProcess(limitedReasons, flags, status, match)

	row := map[string]any{
		"processName":     name,
		"pid":             proc.Pid,
		"path":            privacy.MaskPath(rawPath),
		"commandLine":     commandLine,
		"parentPid":       parentPID,
		"parentName":      parentName,
		"startTime":       startTime,
		"owner":           owner,
		"sessionId":       sessionID,
		"cwd":             cwd,
		"signer":          signature.Signer,
		"publisher":       signature.Publisher,
		"signatureStatus": signature.Status,
		"suspiciousFlags": flags,
		"confidence":      confidence,
		"limitedReasons":  uniqueStringsSorted(limitedReasons),
		"networkSummary":  networkSummaries[proc.Pid],
		"hashPolicy":      "suspicious_or_rule_match_only",
		"status":          status,
		"source":          "gopsutil_process",
	}

	if status == "suspicious" || match.Matched {
		if executableHash, hashStatus := hashExecutableIfAllowed(rawPath); hashStatus != "" {
			row["hashStatus"] = hashStatus
			if executableHash != "" {
				row["executableSha256"] = executableHash
			}
		}
	}

	redactedRow := privacy.RedactMap(row)
	redactedRow["commandLine"] = commandLine
	severity := severityForProcess(status, match)
	var evidence *contract.Evidence
	var finding *contract.Finding
	if status == "suspicious" && policyShouldCreateFinding(status, severity, flags, signature.Status) {
		e, f := buildSuspiciousProcessEvidence(redactedRow, name, proc.Pid, flags, severity, confidence)
		evidence = &e
		finding = &f
	}

	return processIntelligence{
		row:             redactedRow,
		rawPath:         rawPath,
		limited:         coreLimited,
		suspicious:      status == "suspicious",
		shouldHash:      status == "suspicious" || match.Matched,
		stringCandidate: status == "suspicious" || match.Matched,
		evidence:        evidence,
		finding:         finding,
	}
}

func hashExecutableIfAllowed(path string) (string, string) {
	if strings.TrimSpace(path) == "" {
		return "", "path_unavailable"
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", "file_unavailable"
	}
	if info.IsDir() {
		return "", "not_regular_file"
	}
	if info.Size() > int64(MaxExecutableHashMB)*1024*1024 {
		return "", "file_too_large"
	}

	file, err := os.Open(path)
	if err != nil {
		return "", "read_denied"
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", "read_failed"
	}

	return hex.EncodeToString(hash.Sum(nil)), "hashed"
}

func collectWindowsItems(ctx context.Context) ([]map[string]any, []string) {
	items := []map[string]any{}
	warnings := []string{}

	if serviceRows, err := collectServiceItems(); err == nil {
		items = append(items, serviceRows...)
	} else {
		warnings = append(warnings, "services_unavailable")
	}

	if startupRows, err := collectStartupItems(); err == nil {
		items = append(items, startupRows...)
	} else {
		warnings = append(warnings, "startup_entries_unavailable")
	}

	if taskRows, err := collectScheduledTaskItems(ctx); err == nil {
		items = append(items, taskRows...)
	} else {
		warnings = append(warnings, "scheduled_tasks_unavailable")
	}

	if defenderRow, err := collectDefenderSummary(ctx); err == nil {
		items = append(items, defenderRow)
	} else {
		items = append(items, privacy.RedactMap(map[string]any{
			"kind":      "defender_summary",
			"name":      "Microsoft Defender",
			"status":    "limited",
			"source":    "powershell_defender",
			"errorCode": "DEFENDER_SUMMARY_UNAVAILABLE",
		}))
		warnings = append(warnings, "defender_summary_unavailable")
	}

	return items, warnings
}

func collectServiceItems() ([]map[string]any, error) {
	services := []win32Service{}
	if err := wmi.Query("SELECT Name, DisplayName, State, StartMode, PathName FROM Win32_Service", &services); err != nil {
		return nil, err
	}

	rows := []map[string]any{}
	for _, service := range services {
		match := MatchBuiltInUtility(service.Name+" "+service.DisplayName, service.PathName)
		if !match.Matched {
			continue
		}
		rows = append(rows, privacy.RedactMap(map[string]any{
			"kind":        "service",
			"name":        service.Name,
			"displayName": service.DisplayName,
			"state":       service.State,
			"startMode":   service.StartMode,
			"path":        privacy.MaskPath(service.PathName),
			"status":      match.Status,
			"severity":    match.Severity,
			"category":    match.Category,
			"matchedRule": match.RuleID,
			"confidence":  match.Confidence,
			"source":      "wmi_win32_service",
		}))
	}

	return rows, nil
}

func collectStartupItems() ([]map[string]any, error) {
	rows := []map[string]any{}
	errs := []string{}

	registryLocations := []struct {
		root registry.Key
		name string
		path string
	}{
		{registry.CURRENT_USER, "HKCU Run", `Software\Microsoft\Windows\CurrentVersion\Run`},
		{registry.CURRENT_USER, "HKCU RunOnce", `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
		{registry.LOCAL_MACHINE, "HKLM Run", `Software\Microsoft\Windows\CurrentVersion\Run`},
		{registry.LOCAL_MACHINE, "HKLM RunOnce", `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	}

	for _, location := range registryLocations {
		key, err := registry.OpenKey(location.root, location.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, err := key.ReadValueNames(0)
		if err != nil {
			errs = append(errs, location.name)
			_ = key.Close()
			continue
		}
		for _, name := range names {
			value, _, err := key.GetStringValue(name)
			if err != nil {
				continue
			}
			match := MatchBuiltInUtility(name, value)
			if !match.Matched {
				continue
			}
			rows = append(rows, privacy.RedactMap(map[string]any{
				"kind":        "startup_registry",
				"name":        name,
				"path":        privacy.MaskPath(value),
				"registryKey": location.name,
				"status":      match.Status,
				"severity":    match.Severity,
				"category":    match.Category,
				"matchedRule": match.RuleID,
				"confidence":  match.Confidence,
				"source":      "windows_registry_startup",
			}))
		}
		_ = key.Close()
	}

	for _, folder := range startupFolders() {
		entries, err := os.ReadDir(folder.path)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			fullPath := filepath.Join(folder.path, entry.Name())
			match := MatchBuiltInUtility(entry.Name(), fullPath)
			if !match.Matched {
				continue
			}
			modifiedAt := ""
			if info, err := entry.Info(); err == nil {
				modifiedAt = info.ModTime().UTC().Format(time.RFC3339)
			}
			rows = append(rows, privacy.RedactMap(map[string]any{
				"kind":        "startup_folder",
				"name":        entry.Name(),
				"path":        privacy.MaskPath(fullPath),
				"folder":      folder.name,
				"modifiedAt":  modifiedAt,
				"status":      match.Status,
				"severity":    match.Severity,
				"category":    match.Category,
				"matchedRule": match.RuleID,
				"confidence":  match.Confidence,
				"source":      "windows_startup_folder",
			}))
		}
	}

	if len(errs) > 0 && len(rows) == 0 {
		return rows, errors.New(strings.Join(errs, ","))
	}

	return rows, nil
}

func startupFolders() []struct {
	name string
	path string
} {
	return []struct {
		name string
		path string
	}{
		{"current_user_startup", filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`)},
		{"all_users_startup", filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\Startup`)},
	}
}

func collectScheduledTaskItems(ctx context.Context) ([]map[string]any, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	output, err := hiddenCommand(timeoutCtx, "schtasks.exe", "/Query", "/FO", "CSV", "/V").Output()
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(bytes.NewReader(output))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
		return nil, nil
	}

	headers := map[string]int{}
	for index, header := range records[0] {
		headers[strings.ToLower(strings.TrimSpace(header))] = index
	}

	rows := []map[string]any{}
	for _, record := range records[1:] {
		name := csvValue(record, headers, "taskname")
		taskRun := csvValue(record, headers, "task to run")
		status := csvValue(record, headers, "status")
		if name == "" && taskRun == "" {
			continue
		}
		match := MatchBuiltInUtility(name, taskRun)
		if !match.Matched {
			continue
		}
		rows = append(rows, privacy.RedactMap(map[string]any{
			"kind":        "scheduled_task",
			"name":        name,
			"path":        privacy.MaskPath(taskRun),
			"taskStatus":  status,
			"status":      match.Status,
			"severity":    match.Severity,
			"category":    match.Category,
			"matchedRule": match.RuleID,
			"confidence":  match.Confidence,
			"source":      "schtasks_csv",
		}))
	}

	return rows, nil
}

func csvValue(record []string, headers map[string]int, name string) string {
	index, ok := headers[name]
	if !ok || index < 0 || index >= len(record) {
		return ""
	}
	return strings.TrimSpace(record[index])
}

func collectDefenderSummary(ctx context.Context) (map[string]any, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	command := "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,AntispywareEnabled,QuickScanAge,FullScanAge | ConvertTo-Json -Compress"
	output, err := hiddenCommand(timeoutCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command).Output()
	if err != nil {
		return nil, err
	}

	var parsed map[string]any
	if err := json.Unmarshal(output, &parsed); err != nil {
		return nil, err
	}

	enabled := boolValue(parsed["AntivirusEnabled"]) && boolValue(parsed["RealTimeProtectionEnabled"])
	status := "ok"
	severity := "INFO"
	if !enabled {
		status = "review"
		severity = "WARNING"
	}

	row := map[string]any{
		"kind":                      "defender_summary",
		"name":                      "Microsoft Defender",
		"status":                    status,
		"severity":                  severity,
		"source":                    "powershell_defender",
		"amServiceEnabled":          parsed["AMServiceEnabled"],
		"antivirusEnabled":          parsed["AntivirusEnabled"],
		"realTimeProtectionEnabled": parsed["RealTimeProtectionEnabled"],
		"behaviorMonitorEnabled":    parsed["BehaviorMonitorEnabled"],
		"ioavProtectionEnabled":     parsed["IoavProtectionEnabled"],
		"nisEnabled":                parsed["NISEnabled"],
		"antispywareEnabled":        parsed["AntispywareEnabled"],
		"quickScanAge":              normalizeNumber(parsed["QuickScanAge"]),
		"fullScanAge":               normalizeNumber(parsed["FullScanAge"]),
	}

	return privacy.RedactMap(row), nil
}

func boolValue(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		parsed, _ := strconv.ParseBool(typed)
		return parsed
	default:
		return false
	}
}

func normalizeNumber(value any) any {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	default:
		return typed
	}
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
