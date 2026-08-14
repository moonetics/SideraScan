//go:build windows

package windows

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/host"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
	"github.com/moonetics/SideraScan/apps/scanner/internal/privacy"
)

const af4DefaultLookbackDays = 7

type forensicAF4Result struct {
	EventLogs      []map[string]any
	DefenderEvents []map[string]any
	Evidence       []contract.Evidence
	Findings       []contract.Finding
	Summary        map[string]any
	Warnings       []string
}

type psEventRow struct {
	LogName    string `json:"logName"`
	Provider   string `json:"provider"`
	EventID    int    `json:"eventId"`
	RecordID   int64  `json:"recordId"`
	Timestamp  string `json:"timestamp"`
	Level      string `json:"level"`
	Properties []any  `json:"properties"`
}

func collectEventDefenderForensics(ctx context.Context, options BaselineOptions) forensicAF4Result {
	result := forensicAF4Result{}
	reviewMode := forensicReviewMode(options.AdvancedForensics)
	rowLimit := options.AdvancedForensics.MaxRowsPerModule
	if rowLimit <= 0 {
		rowLimit = 500
	}
	startTime := af4StartTime(ctx)
	perSourceLimit := maxInt(25, rowLimit/6)

	eventRows, eventWarnings := collectAF4EventLogs(ctx, startTime, perSourceLimit)
	defenderRows, defenderWarnings := collectAF4DefenderEvents(ctx, startTime, perSourceLimit)
	result.Warnings = append(result.Warnings, eventWarnings...)
	result.Warnings = append(result.Warnings, defenderWarnings...)

	result.EventLogs = filterAF4Rows(eventRows, reviewMode, rowLimit)
	result.DefenderEvents = filterAF4Rows(defenderRows, reviewMode, rowLimit)

	for _, row := range append(append([]map[string]any{}, result.EventLogs...), result.DefenderEvents...) {
		if shouldCreateAF4Finding(row) {
			evidence, finding := buildAF4EvidenceFinding(row)
			result.Evidence = append(result.Evidence, evidence)
			result.Findings = append(result.Findings, finding)
		}
	}

	result.Summary = map[string]any{
		"reviewMode":          reviewMode,
		"lookbackDays":        af4DefaultLookbackDays,
		"startTime":           startTime.UTC().Format(time.RFC3339),
		"eventLogs":           summarizeAF4Rows(eventRows, result.EventLogs),
		"defenderEvents":      summarizeAF4Rows(defenderRows, result.DefenderEvents),
		"bestEffortWarnings":  uniqueStringsSorted(result.Warnings),
		"allMetadataUploaded": reviewMode == "ai_assisted_full",
	}

	return result
}

func af4StartTime(ctx context.Context) time.Time {
	lookback := time.Now().UTC().AddDate(0, 0, -af4DefaultLookbackDays)
	info, err := host.InfoWithContext(ctx)
	if err != nil || info == nil || info.BootTime == 0 {
		return lookback
	}
	boot := time.Unix(int64(info.BootTime), 0).UTC()
	if boot.After(lookback) {
		return boot
	}
	return lookback
}

func collectAF4EventLogs(ctx context.Context, startTime time.Time, perSourceLimit int) ([]map[string]any, []string) {
	queries := []struct {
		logName string
		ids     []int
		source  string
	}{
		{"System", []int{7045}, "windows_system_event_log"},
		{"Security", []int{4688, 4698, 1102}, "windows_security_event_log"},
		{"Application", []int{1033, 11707, 11724}, "windows_application_event_log"},
		{"Microsoft-Windows-TaskScheduler/Operational", []int{106, 140, 141, 200, 201}, "windows_task_scheduler_operational"},
	}

	rows := []map[string]any{}
	warnings := []string{}
	for _, query := range queries {
		events, err := queryWinEvents(ctx, query.logName, query.ids, startTime, perSourceLimit)
		if err != nil {
			warnings = append(warnings, "af4_"+safeKey(query.logName)+"_unavailable")
			continue
		}
		for _, event := range events {
			if row := windowsEventRow(event, query.source); row != nil {
				rows = append(rows, row)
			}
		}
	}
	return rows, warnings
}

func collectAF4DefenderEvents(ctx context.Context, startTime time.Time, perSourceLimit int) ([]map[string]any, []string) {
	rows := []map[string]any{}
	warnings := []string{}

	events, err := queryWinEvents(ctx, "Microsoft-Windows-Windows Defender/Operational", []int{1116, 1117, 1118, 1119, 1121, 5007, 5010, 5012, 5013}, startTime, perSourceLimit)
	if err != nil {
		warnings = append(warnings, "af4_defender_operational_unavailable")
	} else {
		for _, event := range events {
			if row := defenderEventRow(event); row != nil {
				rows = append(rows, row)
			}
		}
	}

	preferenceRows, preferenceWarnings := collectDefenderPreferenceRows(ctx)
	rows = append(rows, preferenceRows...)
	warnings = append(warnings, preferenceWarnings...)

	return rows, warnings
}

func queryWinEvents(ctx context.Context, logName string, ids []int, startTime time.Time, maxEvents int) ([]psEventRow, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	idParts := make([]string, 0, len(ids))
	for _, id := range ids {
		idParts = append(idParts, fmt.Sprintf("%d", id))
	}
	command := fmt.Sprintf(`$ErrorActionPreference='Stop'; $start=[datetime]::Parse(%q); $ids=@(%s); $rows=@(Get-WinEvent -FilterHashtable @{LogName=%q; Id=$ids; StartTime=$start} -MaxEvents %d | Select-Object @{n='logName';e={$_.LogName}},@{n='provider';e={$_.ProviderName}},@{n='eventId';e={$_.Id}},@{n='recordId';e={$_.RecordId}},@{n='timestamp';e={$_.TimeCreated.ToUniversalTime().ToString('o')}},@{n='level';e={$_.LevelDisplayName}},@{n='properties';e={@($_.Properties | ForEach-Object {$_.Value})}}); $rows | ConvertTo-Json -Compress -Depth 5`,
		startTime.UTC().Format(time.RFC3339), strings.Join(idParts, ","), logName, maxEvents)
	output, err := hiddenCommand(timeoutCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command).Output()
	if err != nil {
		return queryWinEventsViaWevtutil(ctx, logName, ids, startTime, maxEvents)
	}
	rows, err := parsePowerShellEventRows(output)
	if err != nil {
		return queryWinEventsViaWevtutil(ctx, logName, ids, startTime, maxEvents)
	}
	return rows, nil
}

func queryWinEventsViaWevtutil(ctx context.Context, logName string, ids []int, startTime time.Time, maxEvents int) ([]psEventRow, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	if maxEvents <= 0 {
		maxEvents = 25
	}
	idQueryParts := make([]string, 0, len(ids))
	for _, id := range ids {
		idQueryParts = append(idQueryParts, fmt.Sprintf("EventID=%d", id))
	}
	lookbackMs := time.Since(startTime).Milliseconds()
	if lookbackMs < 1 {
		lookbackMs = int64(af4DefaultLookbackDays) * 24 * int64(time.Hour/time.Millisecond)
	}
	xpath := fmt.Sprintf("*[System[(%s) and TimeCreated[timediff(@SystemTime) <= %d]]]", strings.Join(idQueryParts, " or "), lookbackMs)
	output, err := hiddenCommand(timeoutCtx, "wevtutil.exe", "qe", logName, "/q:"+xpath, fmt.Sprintf("/c:%d", maxEvents), "/rd:true", "/f:Text").Output()
	if err != nil {
		return nil, err
	}
	return parseWevtutilTextEvents(logName, output), nil
}

func parseWevtutilTextEvents(logName string, output []byte) []psEventRow {
	text := strings.ReplaceAll(string(output), "\r\n", "\n")
	blocks := strings.Split(text, "\nEvent[")
	rows := []psEventRow{}
	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		row := psEventRow{LogName: logName}
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			key = strings.ToLower(strings.TrimSpace(key))
			value = strings.TrimSpace(value)
			switch key {
			case "source":
				row.Provider = value
			case "date":
				row.Timestamp = value
			case "event id":
				row.EventID = intFromString(value)
			case "level":
				row.Level = value
			}
		}
		if row.EventID != 0 {
			rows = append(rows, row)
		}
	}
	return rows
}

func parsePowerShellEventRows(output []byte) ([]psEventRow, error) {
	output = bytes.TrimSpace(output)
	if len(output) == 0 || bytes.Equal(output, []byte("null")) {
		return nil, nil
	}
	var rows []psEventRow
	if err := json.Unmarshal(output, &rows); err == nil {
		return rows, nil
	}
	var row psEventRow
	if err := json.Unmarshal(output, &row); err != nil {
		return nil, err
	}
	return []psEventRow{row}, nil
}

func windowsEventRow(event psEventRow, source string) map[string]any {
	if event.EventID == 0 {
		return nil
	}
	row := baseEventRow(event, source)
	switch event.EventID {
	case 7045:
		row["eventType"] = "service_installed"
		row["title"] = "Service installed"
		row["name"] = safeProperty(event.Properties, 0)
		row["path"] = privacy.MaskPath(executableFromCommand(safeProperty(event.Properties, 1)))
		row["command"] = redactCommandLine(safeProperty(event.Properties, 1))
		row["serviceType"] = safeProperty(event.Properties, 2)
		row["startMode"] = safeProperty(event.Properties, 3)
		row["status"] = "review"
		row["severity"] = "WARNING"
		row["confidence"] = 82
	case 4688:
		newProcess := safeProperty(event.Properties, 5)
		commandLine := safeProperty(event.Properties, 8)
		parentProcess := safeProperty(event.Properties, 13)
		row["eventType"] = "process_created"
		row["title"] = "Process created"
		row["processName"] = filepath.Base(newProcess)
		row["path"] = privacy.MaskPath(newProcess)
		row["command"] = redactCommandLine(commandLine)
		row["parentProcess"] = privacy.MaskPath(parentProcess)
		flags := suspiciousPathFlags(filepath.Base(newProcess), firstNonEmptyString(newProcess, executableFromCommand(commandLine)), signatureInfo{Status: "not_checked"})
		row["suspiciousFlags"] = flags
		row["status"] = "normal"
		row["severity"] = "INFO"
		row["confidence"] = 58
		if len(flags) > 0 {
			row["status"] = "review"
			row["severity"] = "INFO"
			row["confidence"] = 76
		}
	case 4698:
		row["eventType"] = "scheduled_task_created"
		row["title"] = "Scheduled task created"
		row["name"] = safeProperty(event.Properties, 4)
		row["status"] = "review"
		row["severity"] = "INFO"
		row["confidence"] = 78
	case 1102:
		row["eventType"] = "event_log_cleared"
		row["title"] = "Security event log cleared"
		row["status"] = "suspicious"
		row["severity"] = "SEVERE"
		row["confidence"] = 92
		row["suspiciousFlags"] = []string{"event_log_cleared"}
	case 106, 140, 141, 200, 201:
		row["eventType"] = "scheduled_task_activity"
		row["title"] = taskSchedulerTitle(event.EventID)
		row["name"] = safeProperty(event.Properties, 0)
		row["status"] = "context"
		row["severity"] = "INFO"
		row["confidence"] = 55
	default:
		row["eventType"] = "windows_event"
		row["title"] = "Windows event"
		row["status"] = "normal"
		row["severity"] = "INFO"
		row["confidence"] = 45
	}
	return privacy.RedactMap(row)
}

func defenderEventRow(event psEventRow) map[string]any {
	row := baseEventRow(event, "windows_defender_operational")
	row["eventType"] = "defender_event"
	row["title"] = defenderEventTitle(event.EventID)
	row["threatName"] = safeProperty(event.Properties, 0)
	row["path"] = privacy.MaskPath(firstPathLikeProperty(event.Properties))
	row["status"] = "context"
	row["severity"] = "INFO"
	row["confidence"] = 62
	row["metadata"] = map[string]any{
		"propertySummary": safePropertySummary(event.Properties, 8),
	}

	if event.EventID == 1116 || event.EventID == 1117 || event.EventID == 1118 || event.EventID == 1121 {
		row["eventType"] = "defender_detection"
		threat := strings.ToLower(safeProperty(event.Properties, 0) + " " + safeProperty(event.Properties, 1))
		row["suspiciousFlags"] = defenderThreatFlags(threat)
		if len(row["suspiciousFlags"].([]string)) > 0 {
			row["status"] = "suspicious"
			row["severity"] = "SEVERE"
			row["confidence"] = 88
		} else {
			row["status"] = "review"
			row["severity"] = "WARNING"
			row["confidence"] = 76
		}
	}
	if event.EventID == 5007 || event.EventID == 5013 {
		row["eventType"] = "defender_config_changed"
		row["suspiciousFlags"] = []string{"defender_config_changed"}
		row["status"] = "context"
		row["severity"] = "INFO"
		row["confidence"] = 65
	}
	return privacy.RedactMap(row)
}

func baseEventRow(event psEventRow, source string) map[string]any {
	return map[string]any{
		"timestamp":       normalizeEventTimestamp(event.Timestamp),
		"channel":         event.LogName,
		"provider":        event.Provider,
		"eventId":         event.EventID,
		"recordId":        event.RecordID,
		"level":           event.Level,
		"source":          source,
		"rawXmlUploaded":  false,
		"fullMessageSent": false,
	}
}

func collectDefenderPreferenceRows(ctx context.Context) ([]map[string]any, []string) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	command := `$ErrorActionPreference='Stop'; $status=Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,AntispywareEnabled; $pref=Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension,ExclusionIpAddress; [pscustomobject]@{status=$status; preference=$pref} | ConvertTo-Json -Compress -Depth 5`
	output, err := hiddenCommand(timeoutCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command).Output()
	if err != nil {
		return nil, []string{"af4_defender_preference_unavailable"}
	}

	var parsed map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output), &parsed); err != nil {
		return nil, []string{"af4_defender_preference_parse_failed"}
	}

	rows := []map[string]any{}
	status := objectFromAny(parsed["status"])
	enabled := boolValue(status["AntivirusEnabled"]) && boolValue(status["RealTimeProtectionEnabled"])
	statusRow := map[string]any{
		"forensicSource":              "defender",
		"eventType":                   "defender_status",
		"title":                       "Microsoft Defender status",
		"name":                        "Microsoft Defender",
		"status":                      "normal",
		"severity":                    "INFO",
		"source":                      "powershell_defender_preference",
		"confidence":                  82,
		"amServiceEnabled":            status["AMServiceEnabled"],
		"antivirusEnabled":            status["AntivirusEnabled"],
		"realTimeProtectionEnabled":   status["RealTimeProtectionEnabled"],
		"behaviorMonitorEnabled":      status["BehaviorMonitorEnabled"],
		"ioavProtectionEnabled":       status["IoavProtectionEnabled"],
		"networkInspectionEnabled":    status["NISEnabled"],
		"antispywareEnabled":          status["AntispywareEnabled"],
		"rawXmlUploaded":              false,
		"fullDefenderHistoryUploaded": false,
	}
	if !enabled {
		statusRow["status"] = "review"
		statusRow["severity"] = "WARNING"
		statusRow["suspiciousFlags"] = []string{"defender_protection_reduced"}
	}
	rows = append(rows, privacy.RedactMap(statusRow))

	preference := objectFromAny(parsed["preference"])
	rows = append(rows, defenderExclusionRows("path", preference["ExclusionPath"])...)
	rows = append(rows, defenderExclusionRows("process", preference["ExclusionProcess"])...)
	rows = append(rows, defenderExclusionRows("extension", preference["ExclusionExtension"])...)
	rows = append(rows, defenderExclusionRows("ip", preference["ExclusionIpAddress"])...)

	return rows, nil
}

func defenderExclusionRows(exclusionType string, value any) []map[string]any {
	items := stringsFromUnknown(value)
	rows := make([]map[string]any, 0, len(items))
	for _, item := range items {
		cleanValue := sanitizeDefenderExclusion(exclusionType, item)
		flags := defenderExclusionFlags(exclusionType, item)
		status := "normal"
		severity := "INFO"
		confidence := 55
		if len(flags) > 0 {
			status = "review"
			severity = "INFO"
			confidence = 82
			if policyStrongSignalCount(flags, "") >= 2 {
				severity = "WARNING"
			}
		}
		rows = append(rows, privacy.RedactMap(map[string]any{
			"forensicSource":  "defender",
			"eventType":       "defender_exclusion",
			"title":           "Microsoft Defender exclusion",
			"name":            exclusionType + " exclusion",
			"exclusionType":   exclusionType,
			"value":           cleanValue,
			"path":            cleanValue,
			"status":          status,
			"severity":        severity,
			"source":          "powershell_get_mppreference",
			"confidence":      confidence,
			"suspiciousFlags": flags,
		}))
	}
	return rows
}

func filterAF4Rows(rows []map[string]any, reviewMode string, limit int) []map[string]any {
	filtered := []map[string]any{}
	for _, row := range rows {
		status := strings.ToLower(stringFromAny(row["status"]))
		if reviewMode == "ai_assisted_full" || status == "review" || status == "suspicious" || status == "flagged" {
			filtered = append(filtered, row)
		}
		if limit > 0 && len(filtered) >= limit {
			break
		}
	}
	return filtered
}

func summarizeAF4Rows(allRows []map[string]any, uploadedRows []map[string]any) map[string]any {
	statusCounts := map[string]int{}
	severityCounts := map[string]int{}
	for _, row := range allRows {
		status := firstNonEmptyString(stringFromAny(row["status"]), "unknown")
		severity := firstNonEmptyString(stringFromAny(row["severity"]), "INFO")
		statusCounts[status]++
		severityCounts[severity]++
	}
	return map[string]any{
		"total":          len(allRows),
		"uploaded":       len(uploadedRows),
		"statusCounts":   statusCounts,
		"severityCounts": severityCounts,
	}
}

func shouldCreateAF4Finding(row map[string]any) bool {
	status := strings.ToLower(stringFromAny(row["status"]))
	eventType := strings.ToLower(stringFromAny(row["eventType"]))
	if eventType == "event_log_cleared" {
		return true
	}
	flags := stringsFromUnknown(row["suspiciousFlags"])
	if strings.Contains(eventType, "defender") && len(flags) > 0 {
		return strings.ToUpper(stringFromAny(row["severity"])) == "WARNING" ||
			strings.ToUpper(stringFromAny(row["severity"])) == "SEVERE" ||
			strings.Contains(strings.Join(flags, " "), "exclusion")
	}
	return policyShouldCreateFinding(status, stringFromAny(row["severity"]), flags, "")
}

func buildAF4EvidenceFinding(row map[string]any) (contract.Evidence, contract.Finding) {
	title := firstNonEmptyString(stringFromAny(row["title"]), stringFromAny(row["name"]), "Event requires review")
	eventType := firstNonEmptyString(stringFromAny(row["eventType"]), "event_log")
	evidenceID := fmt.Sprintf("af4-%s-%x", eventType, fnv32(title+stringFromAny(row["timestamp"])+stringFromAny(row["path"])))
	severity := firstNonEmptyString(stringFromAny(row["severity"]), "WARNING")
	evidence := contract.Evidence{
		ClientEvidenceID: evidenceID,
		Type:             eventType,
		Title:            "Event/Defender artifact: " + title,
		Data:             privacy.RedactMap(row),
	}
	finding := contract.Finding{
		Category:     "WINDOWS_ITEM",
		Severity:     severity,
		Title:        title,
		Message:      "A Windows Event Log or Microsoft Defender artifact matched forensic review heuristics.",
		EvidenceRef:  evidenceID,
		Confidence:   intFromAnyDefault(row["confidence"], 80),
		SourceModule: "event_logs_defender",
		Metadata: privacy.RedactMap(map[string]any{
			"eventType":       eventType,
			"eventId":         row["eventId"],
			"channel":         row["channel"],
			"provider":        row["provider"],
			"path":            row["path"],
			"status":          row["status"],
			"suspiciousFlags": row["suspiciousFlags"],
		}),
	}
	return evidence, finding
}

func safeProperty(values []any, index int) string {
	if index < 0 || index >= len(values) {
		return ""
	}
	return privacy.RedactString(fmt.Sprint(values[index]))
}

func safePropertySummary(values []any, maxItems int) []string {
	out := []string{}
	for _, value := range values {
		text := strings.TrimSpace(fmt.Sprint(value))
		if text == "" || looksLikeRawXML(text) {
			continue
		}
		if len(text) > 240 {
			text = text[:240]
		}
		out = append(out, privacy.RedactString(text))
		if len(out) >= maxItems {
			break
		}
	}
	return out
}

func firstPathLikeProperty(values []any) string {
	for _, value := range values {
		text := fmt.Sprint(value)
		if strings.Contains(text, `:\`) || strings.Contains(text, ":/") {
			return privacy.RedactString(text)
		}
	}
	return ""
}

func looksLikeRawXML(value string) bool {
	trimmed := strings.TrimSpace(value)
	return strings.HasPrefix(trimmed, "<") && strings.Contains(trimmed, ">")
}

func normalizeEventTimestamp(value string) string {
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC().Format(time.RFC3339)
	}
	return privacy.RedactString(value)
}

func taskSchedulerTitle(eventID int) string {
	switch eventID {
	case 106:
		return "Scheduled task registered"
	case 140:
		return "Scheduled task updated"
	case 141:
		return "Scheduled task deleted"
	case 200:
		return "Scheduled task action started"
	case 201:
		return "Scheduled task action completed"
	default:
		return "Scheduled task activity"
	}
}

func defenderEventTitle(eventID int) string {
	switch eventID {
	case 1116:
		return "Defender threat detected"
	case 1117:
		return "Defender remediation completed"
	case 1118:
		return "Defender remediation failed"
	case 1119:
		return "Defender remediation pending"
	case 1121:
		return "Defender threat blocked"
	case 5007:
		return "Defender configuration changed"
	case 5010, 5012, 5013:
		return "Defender protection changed"
	default:
		return "Defender operational event"
	}
}

func defenderThreatFlags(threat string) []string {
	flags := []string{}
	for _, marker := range []string{"hacktool", "injector", "pua", "driver", "exploit", "cheat", "loader"} {
		if strings.Contains(threat, marker) {
			flags = append(flags, "defender_"+marker+"_detection")
		}
	}
	return uniqueStringsSorted(flags)
}

func sanitizeDefenderExclusion(exclusionType string, value string) string {
	if exclusionType == "ip" {
		return "[REDACTED_IP]"
	}
	if exclusionType == "extension" {
		return strings.TrimSpace(value)
	}
	return privacy.RedactString(value)
}

func defenderExclusionFlags(exclusionType string, value string) []string {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(strings.ReplaceAll(value, "/", `\`))
	flags := []string{}
	switch exclusionType {
	case "path":
		if isUserWritablePath(lower) {
			flags = append(flags, "defender_exclusion_user_writable_path")
		}
		if strings.Contains(lower, `\temp`) || strings.Contains(lower, `\downloads`) {
			flags = append(flags, "defender_exclusion_download_or_temp")
		}
	case "process":
		if isUserWritablePath(lower) || strings.Contains(lower, `\temp`) || strings.Contains(lower, `\downloads`) {
			flags = append(flags, "defender_exclusion_suspicious_process")
		}
	case "extension":
		if lower == ".exe" || lower == "exe" || lower == ".dll" || lower == "dll" || lower == ".sys" || lower == "sys" || lower == ".ps1" || lower == "ps1" {
			flags = append(flags, "defender_exclusion_executable_extension")
		}
	case "ip":
		if value != "" {
			flags = append(flags, "defender_exclusion_ip")
		}
	}
	return uniqueStringsSorted(flags)
}

func stringsFromUnknown(value any) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{typed}
	case []any:
		out := []string{}
		for _, item := range typed {
			if text := strings.TrimSpace(fmt.Sprint(item)); text != "" {
				out = append(out, text)
			}
		}
		return out
	case []string:
		return typed
	default:
		text := strings.TrimSpace(fmt.Sprint(value))
		if text == "" {
			return nil
		}
		return []string{text}
	}
}

func objectFromAny(value any) map[string]any {
	if mapping, ok := value.(map[string]any); ok {
		return mapping
	}
	return map[string]any{}
}

func intFromString(value string) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0
	}
	return parsed
}

func safeKey(value string) string {
	value = strings.ToLower(value)
	replacer := strings.NewReplacer("\\", "_", "/", "_", " ", "_", "-", "_")
	return replacer.Replace(value)
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
