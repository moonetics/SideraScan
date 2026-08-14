//go:build windows

package windows

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/StackExchange/wmi"
	"golang.org/x/sys/windows/registry"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
	"github.com/moonetics/SideraScan/apps/scanner/internal/privacy"
)

type forensicAF3Result struct {
	Services         []map[string]any
	Drivers          []map[string]any
	PersistenceItems []map[string]any
	Evidence         []contract.Evidence
	Findings         []contract.Finding
	Summary          map[string]any
	Warnings         []string
}

type win32Driver struct {
	Name        string
	DisplayName string
	State       string
	StartMode   string
	PathName    string
}

type forensicItem struct {
	Module      string
	Kind        string
	Name        string
	DisplayName string
	Path        string
	Command     string
	Location    string
	State       string
	StartMode   string
	Source      string
	Metadata    map[string]any
}

func collectServiceDriverPersistenceForensics(ctx context.Context, options BaselineOptions, signatureCache map[string]signatureInfo) forensicAF3Result {
	result := forensicAF3Result{}
	reviewMode := forensicReviewMode(options.AdvancedForensics)
	rowLimit := options.AdvancedForensics.MaxRowsPerModule
	if rowLimit <= 0 {
		rowLimit = 500
	}
	maxHashMB := options.AdvancedForensics.MaxFileHashMB
	if maxHashMB <= 0 {
		maxHashMB = MaxExecutableHashMB
	}

	services, serviceWarnings := collectAF3Services(ctx, maxHashMB, signatureCache)
	drivers, driverWarnings := collectAF3Drivers(ctx, maxHashMB, signatureCache)
	persistence, persistenceWarnings := collectAF3Persistence(ctx, maxHashMB, signatureCache)
	result.Warnings = append(result.Warnings, serviceWarnings...)
	result.Warnings = append(result.Warnings, driverWarnings...)
	result.Warnings = append(result.Warnings, persistenceWarnings...)

	result.Services = filterAF3Rows(services, reviewMode, rowLimit)
	result.Drivers = filterAF3Rows(drivers, reviewMode, rowLimit)
	result.PersistenceItems = filterAF3Rows(persistence, reviewMode, rowLimit)

	for _, row := range append(append([]map[string]any{}, result.Services...), append(result.Drivers, result.PersistenceItems...)...) {
		if shouldCreateAF3Finding(row) {
			evidence, finding := buildAF3EvidenceFinding(row)
			result.Evidence = append(result.Evidence, evidence)
			result.Findings = append(result.Findings, finding)
		}
	}

	result.Summary = map[string]any{
		"reviewMode":          reviewMode,
		"services":            summarizeAF3Rows(services, result.Services),
		"drivers":             summarizeAF3Rows(drivers, result.Drivers),
		"persistenceItems":    summarizeAF3Rows(persistence, result.PersistenceItems),
		"bestEffortWarnings":  uniqueStringsSorted(result.Warnings),
		"allMetadataUploaded": reviewMode == "ai_assisted_full",
	}

	return result
}

func forensicReviewMode(config contract.AdvancedForensicsConfig) string {
	if strings.EqualFold(config.ReviewMode, "ai_assisted_full") {
		return "ai_assisted_full"
	}
	return "review_relevant_only"
}

func collectAF3Services(ctx context.Context, maxHashMB int, signatureCache map[string]signatureInfo) ([]map[string]any, []string) {
	services := []win32Service{}
	if err := wmi.Query("SELECT Name, DisplayName, State, StartMode, PathName FROM Win32_Service", &services); err != nil {
		return nil, []string{"af3_services_unavailable"}
	}

	rows := make([]map[string]any, 0, len(services))
	for _, service := range services {
		item := forensicItem{
			Module:      "services",
			Kind:        "service",
			Name:        service.Name,
			DisplayName: service.DisplayName,
			Path:        executableFromCommand(service.PathName),
			Command:     service.PathName,
			Location:    "Win32_Service",
			State:       service.State,
			StartMode:   service.StartMode,
			Source:      "wmi_win32_service",
			Metadata:    map[string]any{"serviceState": service.State, "startMode": service.StartMode},
		}
		rows = append(rows, af3Row(ctx, item, maxHashMB, signatureCache))
	}
	return rows, nil
}

func collectAF3Drivers(ctx context.Context, maxHashMB int, signatureCache map[string]signatureInfo) ([]map[string]any, []string) {
	drivers := []win32Driver{}
	warnings := []string{}
	if err := wmi.Query("SELECT Name, DisplayName, State, StartMode, PathName FROM Win32_SystemDriver", &drivers); err != nil {
		warnings = append(warnings, "af3_drivers_wmi_unavailable")
	}

	rows := []map[string]any{}
	seen := map[string]bool{}
	for _, driver := range drivers {
		pathValue := normalizeDriverPath(driver.PathName)
		item := forensicItem{
			Module:      "drivers",
			Kind:        "driver",
			Name:        driver.Name,
			DisplayName: driver.DisplayName,
			Path:        pathValue,
			Command:     driver.PathName,
			Location:    "Win32_SystemDriver",
			State:       driver.State,
			StartMode:   driver.StartMode,
			Source:      "wmi_win32_system_driver",
			Metadata:    map[string]any{"loadedState": driver.State, "startMode": driver.StartMode},
		}
		rows = append(rows, af3Row(ctx, item, maxHashMB, signatureCache))
		seen[strings.ToLower(driver.Name)] = true
	}

	registryRows, registryWarnings := collectRegistryDriverRows(ctx, maxHashMB, signatureCache, seen)
	rows = append(rows, registryRows...)
	warnings = append(warnings, registryWarnings...)
	return rows, warnings
}

func collectRegistryDriverRows(ctx context.Context, maxHashMB int, signatureCache map[string]signatureInfo, seen map[string]bool) ([]map[string]any, []string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil, []string{"af3_driver_registry_unavailable"}
	}
	defer key.Close()

	names, err := key.ReadSubKeyNames(0)
	if err != nil {
		return nil, []string{"af3_driver_registry_names_unavailable"}
	}

	rows := []map[string]any{}
	for _, name := range names {
		if seen[strings.ToLower(name)] {
			continue
		}
		sub, err := registry.OpenKey(key, name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		typeValue, _, _ := sub.GetIntegerValue("Type")
		imagePath, _, _ := sub.GetStringValue("ImagePath")
		startValue, _, _ := sub.GetIntegerValue("Start")
		_ = sub.Close()
		if typeValue != 1 && typeValue != 2 {
			continue
		}
		pathValue := normalizeDriverPath(imagePath)
		item := forensicItem{
			Module:    "drivers",
			Kind:      "driver_registry",
			Name:      name,
			Path:      pathValue,
			Command:   imagePath,
			Location:  `HKLM\SYSTEM\CurrentControlSet\Services\` + name,
			StartMode: fmt.Sprintf("registry_start_%d", startValue),
			Source:    "windows_registry_driver",
			Metadata:  map[string]any{"registryType": typeValue, "registryStart": startValue},
		}
		rows = append(rows, af3Row(ctx, item, maxHashMB, signatureCache))
	}
	return rows, nil
}

func collectAF3Persistence(ctx context.Context, maxHashMB int, signatureCache map[string]signatureInfo) ([]map[string]any, []string) {
	rows := []map[string]any{}
	warnings := []string{}

	regRows, regWarnings := collectRegistryPersistence(ctx, maxHashMB, signatureCache)
	rows = append(rows, regRows...)
	warnings = append(warnings, regWarnings...)

	folderRows, folderWarnings := collectStartupFolderPersistence(ctx, maxHashMB, signatureCache)
	rows = append(rows, folderRows...)
	warnings = append(warnings, folderWarnings...)

	taskRows, taskWarnings := collectScheduledTaskPersistence(ctx, maxHashMB, signatureCache)
	rows = append(rows, taskRows...)
	warnings = append(warnings, taskWarnings...)

	wmiRows, wmiWarnings := collectWMIPersistence(ctx)
	rows = append(rows, wmiRows...)
	warnings = append(warnings, wmiWarnings...)

	return rows, warnings
}

func collectRegistryPersistence(ctx context.Context, maxHashMB int, signatureCache map[string]signatureInfo) ([]map[string]any, []string) {
	type source struct {
		root registry.Key
		hive string
		path string
		kind string
	}
	sources := []source{
		{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows\CurrentVersion\Run`, "run_key"},
		{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows\CurrentVersion\RunOnce`, "run_once"},
		{registry.LOCAL_MACHINE, "HKLM", `Software\Microsoft\Windows\CurrentVersion\Run`, "run_key"},
		{registry.LOCAL_MACHINE, "HKLM", `Software\Microsoft\Windows\CurrentVersion\RunOnce`, "run_once"},
		{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, "ifeo"},
		{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, "appinit_dlls"},
		{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "winlogon"},
		{registry.LOCAL_MACHINE, "HKLM", `SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`, "known_dlls"},
		{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved`, "shell_extension"},
		{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved`, "shell_extension"},
	}

	rows := []map[string]any{}
	warnings := []string{}
	for _, src := range sources {
		key, err := registry.OpenKey(src.root, src.path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		valueNames, err := key.ReadValueNames(0)
		if err != nil {
			warnings = append(warnings, "af3_registry_values_limited")
		}
		for _, valueName := range valueNames {
			value, _, err := key.GetStringValue(valueName)
			if err != nil {
				continue
			}
			if !shouldCollectRegistryPersistenceValue(src.kind, valueName, value) {
				continue
			}
			pathValue := executableFromCommand(value)
			item := forensicItem{
				Module:   "persistence",
				Kind:     src.kind,
				Name:     valueName,
				Path:     pathValue,
				Command:  value,
				Location: src.hive + `\` + src.path,
				Source:   "windows_registry_persistence",
				Metadata: map[string]any{"registryHive": src.hive},
			}
			rows = append(rows, af3Row(ctx, item, maxHashMB, signatureCache))
		}
		if src.kind == "ifeo" {
			subRows := collectIFEODebuggers(ctx, key, src.hive+`\`+src.path, maxHashMB, signatureCache)
			rows = append(rows, subRows...)
		}
		_ = key.Close()
	}
	return rows, warnings
}

func shouldCollectRegistryPersistenceValue(kind string, valueName string, value string) bool {
	lowerKind := strings.ToLower(kind)
	lowerName := strings.ToLower(valueName)
	lowerValue := strings.ToLower(value)
	if strings.TrimSpace(value) == "" {
		return false
	}
	switch lowerKind {
	case "winlogon":
		if lowerName == "shell" || lowerName == "userinit" || lowerName == "taskman" || lowerName == "ginadll" {
			return true
		}
		return strings.Contains(lowerValue, ".exe") || strings.Contains(lowerValue, ".dll")
	case "known_dlls":
		return isUserWritablePath(strings.ReplaceAll(lowerValue, "/", `\`))
	case "appinit_dlls":
		return strings.Contains(lowerValue, ".dll")
	case "shell_extension":
		return strings.Contains(lowerValue, ".dll") || strings.Contains(lowerValue, ".exe")
	default:
		return true
	}
}

func collectIFEODebuggers(ctx context.Context, key registry.Key, location string, maxHashMB int, signatureCache map[string]signatureInfo) []map[string]any {
	subNames, err := key.ReadSubKeyNames(0)
	if err != nil {
		return nil
	}
	rows := []map[string]any{}
	for _, subName := range subNames {
		sub, err := registry.OpenKey(key, subName, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		debugger, _, err := sub.GetStringValue("Debugger")
		_ = sub.Close()
		if err != nil || strings.TrimSpace(debugger) == "" {
			continue
		}
		item := forensicItem{
			Module:   "persistence",
			Kind:     "ifeo_debugger",
			Name:     subName,
			Path:     executableFromCommand(debugger),
			Command:  debugger,
			Location: location + `\` + subName,
			Source:   "windows_registry_ifeo",
			Metadata: map[string]any{"ifeoTarget": subName},
		}
		rows = append(rows, af3Row(ctx, item, maxHashMB, signatureCache))
	}
	return rows
}

func collectStartupFolderPersistence(ctx context.Context, maxHashMB int, signatureCache map[string]signatureInfo) ([]map[string]any, []string) {
	rows := []map[string]any{}
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
			item := forensicItem{
				Module:   "persistence",
				Kind:     "startup_folder",
				Name:     entry.Name(),
				Path:     fullPath,
				Command:  fullPath,
				Location: folder.name,
				Source:   "windows_startup_folder",
			}
			rows = append(rows, af3Row(ctx, item, maxHashMB, signatureCache))
		}
	}
	return rows, nil
}

func collectScheduledTaskPersistence(ctx context.Context, maxHashMB int, signatureCache map[string]signatureInfo) ([]map[string]any, []string) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()

	output, err := hiddenCommand(timeoutCtx, "schtasks.exe", "/Query", "/FO", "CSV", "/V").Output()
	if err != nil {
		return nil, []string{"af3_scheduled_tasks_unavailable"}
	}
	reader := csv.NewReader(bytes.NewReader(output))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		return nil, []string{"af3_scheduled_tasks_parse_failed"}
	}
	headers := map[string]int{}
	for index, header := range records[0] {
		headers[strings.ToLower(strings.TrimSpace(header))] = index
	}
	rows := []map[string]any{}
	for _, record := range records[1:] {
		name := csvValue(record, headers, "taskname")
		taskRun := csvValue(record, headers, "task to run")
		if strings.TrimSpace(name) == "" && strings.TrimSpace(taskRun) == "" {
			continue
		}
		item := forensicItem{
			Module:   "persistence",
			Kind:     "scheduled_task",
			Name:     name,
			Path:     executableFromCommand(taskRun),
			Command:  taskRun,
			Location: "Task Scheduler",
			Source:   "schtasks_csv",
			Metadata: map[string]any{
				"taskStatus":    csvValue(record, headers, "status"),
				"lastRunTime":   csvValue(record, headers, "last run time"),
				"nextRunTime":   csvValue(record, headers, "next run time"),
				"scheduledTask": true,
			},
		}
		rows = append(rows, af3Row(ctx, item, maxHashMB, signatureCache))
	}
	return rows, nil
}

func collectWMIPersistence(ctx context.Context) ([]map[string]any, []string) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := "Get-CimInstance -Namespace root/subscription -ClassName __EventFilter,__EventConsumer,__FilterToConsumerBinding -ErrorAction Stop | Select-Object __CLASS,Name | ConvertTo-Json -Compress"
	output, err := hiddenCommand(timeoutCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command).Output()
	if err != nil {
		return nil, []string{"af3_wmi_persistence_unavailable"}
	}
	var parsed []map[string]any
	if err := json.Unmarshal(output, &parsed); err != nil {
		var single map[string]any
		if err := json.Unmarshal(output, &single); err != nil {
			return nil, []string{"af3_wmi_persistence_parse_failed"}
		}
		parsed = []map[string]any{single}
	}
	rows := []map[string]any{}
	for _, item := range parsed {
		name := stringFromAny(item["Name"])
		className := stringFromAny(item["__CLASS"])
		rows = append(rows, privacy.RedactMap(map[string]any{
			"module":          "persistence",
			"kind":            "wmi_persistence",
			"name":            firstNonEmptyString(name, className),
			"persistenceType": "wmi_persistence",
			"location":        "root/subscription",
			"source":          "powershell_cim_wmi_subscription",
			"confidence":      82,
			"status":          "review",
			"severity":        "WARNING",
			"suspiciousFlags": []string{"wmi_persistence"},
			"metadata":        privacy.RedactMap(item),
		}))
	}
	return rows, nil
}

func af3Row(ctx context.Context, item forensicItem, maxHashMB int, signatureCache map[string]signatureInfo) map[string]any {
	pathValue := firstNonEmptyString(item.Path, executableFromCommand(item.Command))
	signature := cachedSignature(ctx, pathValue, signatureCache)
	normalDefault := policyIsNormalPersistenceDefault(item.Kind, item.Name, item.Command, pathValue, item.Location)
	flags := af3SuspiciousFlags(item, pathValue, signature)
	missingFile := false
	if strings.TrimSpace(pathValue) != "" {
		if _, err := os.Stat(pathValue); err != nil {
			if !normalDefault {
				missingFile = true
				flags = append(flags, "missing_file")
			}
		}
	}
	flags = uniqueStringsSorted(flags)
	status := af3Status(flags, signature)
	if normalDefault || policyIsKnownVendorArtifact(item.Name, pathValue, signature.Publisher, signature.Signer) && status == "review" {
		status = "normal"
		flags = uniqueStringsSorted(append(flags, "benign_known_vendor_or_windows_default"))
	}
	severity := "INFO"
	if status == "suspicious" || status == "missing_file" {
		severity = "WARNING"
	}
	confidence := 60
	if status != "normal" {
		confidence = 80
	}
	row := map[string]any{
		"module":          item.Module,
		"kind":            item.Kind,
		"name":            item.Name,
		"displayName":     item.DisplayName,
		"path":            privacy.MaskPath(pathValue),
		"command":         redactCommandLine(item.Command),
		"location":        privacy.RedactString(item.Location),
		"state":           item.State,
		"startMode":       item.StartMode,
		"signer":          signature.Signer,
		"publisher":       signature.Publisher,
		"signatureStatus": signature.Status,
		"missingFile":     missingFile,
		"createdTime":     fileCreatedTime(pathValue),
		"modifiedTime":    fileModifiedTime(pathValue),
		"source":          item.Source,
		"confidence":      confidence,
		"status":          status,
		"severity":        severity,
		"suspiciousFlags": flags,
		"limitedReasons":  limitedReasonsFromSignature(signature),
		"hashPolicy":      "suspicious_or_rule_match_only",
		"metadata":        privacy.RedactMap(item.Metadata),
	}
	if item.Module == "drivers" {
		row["outsideSystem32Drivers"] = driverOutsideSystem32(pathValue)
	}
	if status != "normal" {
		if executableHash, hashStatus := hashExecutableIfAllowedMax(pathValue, maxHashMB); hashStatus != "" {
			row["hashStatus"] = hashStatus
			if executableHash != "" {
				row["sha256"] = executableHash
			}
		}
	}
	return privacy.RedactMap(row)
}

func af3SuspiciousFlags(item forensicItem, pathValue string, signature signatureInfo) []string {
	flags := suspiciousPathFlags(item.Name, pathValue, signature)
	normalizedPath := strings.ToLower(strings.ReplaceAll(pathValue, "/", `\`))
	command := strings.ToLower(item.Command)
	if item.Kind == "ifeo_debugger" {
		flags = append(flags, "ifeo_debugger")
	}
	if item.Kind == "appinit_dlls" && strings.TrimSpace(item.Command) != "" {
		flags = append(flags, "appinit_dlls")
	}
	if item.Kind == "winlogon" && strings.TrimSpace(item.Command) != "" && !strings.Contains(command, "userinit.exe") && !strings.Contains(command, "explorer.exe") {
		flags = append(flags, "winlogon_override")
	}
	if item.Kind == "known_dlls" && strings.TrimSpace(item.Command) != "" && isUserWritablePath(normalizedPath) {
		flags = append(flags, "known_dll_user_path")
	}
	if item.Kind == "scheduled_task" && looksLikeWindowsMaintenanceName(item.Name) && isUserWritablePath(normalizedPath) {
		flags = append(flags, "windows_like_task_user_path")
	}
	if commandUsesScriptOrLolbin(command) && isUserWritablePath(normalizedPath+" "+command) {
		flags = append(flags, "script_or_lolbin_persistence")
	}
	if item.Module == "drivers" {
		if driverOutsideSystem32(pathValue) {
			flags = append(flags, "driver_outside_system32_drivers")
		}
		if strings.Contains(command, "mapper") || strings.Contains(command, "kdmapper") || strings.Contains(command, "driverloader") {
			flags = append(flags, "driver_mapper_keyword")
		}
	}
	return flags
}

func af3Status(flags []string, signature signatureInfo) string {
	if containsString(flags, "missing_file") {
		return "missing_file"
	}
	if containsString(flags, "ifeo_debugger") ||
		containsString(flags, "appinit_dlls") ||
		containsString(flags, "winlogon_override") ||
		containsString(flags, "driver_mapper_keyword") {
		return "suspicious"
	}
	if len(flags) > 0 || signature.Status == "unsigned" {
		return "review"
	}
	return "normal"
}

func filterAF3Rows(rows []map[string]any, reviewMode string, limit int) []map[string]any {
	filtered := []map[string]any{}
	for _, row := range rows {
		status := strings.ToLower(stringFromAny(row["status"]))
		if reviewMode == "ai_assisted_full" || status == "review" || status == "suspicious" || status == "missing_file" {
			filtered = append(filtered, row)
		}
		if limit > 0 && len(filtered) >= limit {
			break
		}
	}
	return filtered
}

func summarizeAF3Rows(allRows []map[string]any, uploadedRows []map[string]any) map[string]any {
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

func shouldCreateAF3Finding(row map[string]any) bool {
	status := strings.ToLower(stringFromAny(row["status"]))
	severity := strings.ToUpper(stringFromAny(row["severity"]))
	return policyShouldCreateFinding(status, severity, stringsFromUnknown(row["suspiciousFlags"]), stringFromAny(row["signatureStatus"]))
}

func buildAF3EvidenceFinding(row map[string]any) (contract.Evidence, contract.Finding) {
	name := firstNonEmptyString(stringFromAny(row["name"]), stringFromAny(row["displayName"]), "Persistence item")
	module := firstNonEmptyString(stringFromAny(row["module"]), "persistence")
	evidenceID := fmt.Sprintf("af3-%s-%x", module, fnv32(name+stringFromAny(row["location"])+stringFromAny(row["path"])))
	evidence := contract.Evidence{
		ClientEvidenceID: evidenceID,
		Type:             module,
		Title:            "Service/driver/persistence artifact: " + name,
		Data:             privacy.RedactMap(row),
	}
	finding := contract.Finding{
		Category:     "PROCESS",
		Severity:     firstNonEmptyString(stringFromAny(row["severity"]), "WARNING"),
		Title:        "Persistence artifact requires review: " + name,
		Message:      "A service, driver, or autorun artifact matched forensic review heuristics.",
		EvidenceRef:  evidenceID,
		Confidence:   intFromAnyDefault(row["confidence"], 80),
		SourceModule: module,
		Metadata: privacy.RedactMap(map[string]any{
			"module":          module,
			"kind":            row["kind"],
			"name":            name,
			"path":            row["path"],
			"location":        row["location"],
			"status":          row["status"],
			"suspiciousFlags": row["suspiciousFlags"],
			"signatureStatus": row["signatureStatus"],
			"hashPrefix":      shortHashString(row["sha256"]),
		}),
	}
	return evidence, finding
}

func executableFromCommand(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return ""
	}
	if strings.HasPrefix(command, `"`) {
		end := strings.Index(command[1:], `"`)
		if end >= 0 {
			return command[1 : end+1]
		}
	}
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return ""
	}
	first := strings.Trim(parts[0], `"`)
	if strings.EqualFold(first, "cmd.exe") || strings.EqualFold(first, "powershell.exe") || strings.EqualFold(first, "pwsh.exe") {
		return first
	}
	return strings.Trim(first, `"`)
}

func normalizeDriverPath(value string) string {
	value = strings.TrimSpace(strings.Trim(value, `"`))
	if value == "" {
		return ""
	}
	value = strings.TrimPrefix(value, `\??\`)
	value = strings.TrimPrefix(value, `\\?\`)
	if strings.HasPrefix(strings.ToLower(value), `system32\`) {
		return filepath.Join(os.Getenv("WINDIR"), value)
	}
	if strings.HasPrefix(strings.ToLower(value), `\systemroot\`) {
		return filepath.Join(os.Getenv("WINDIR"), strings.TrimPrefix(value, `\SystemRoot\`))
	}
	if strings.HasPrefix(strings.ToLower(value), `systemroot\`) {
		return filepath.Join(os.Getenv("WINDIR"), strings.TrimPrefix(value, `SystemRoot\`))
	}
	return value
}

func driverOutsideSystem32(pathValue string) bool {
	pathValue = strings.ToLower(strings.ReplaceAll(normalizeDriverPath(pathValue), "/", `\`))
	if strings.TrimSpace(pathValue) == "" {
		return false
	}
	systemRoot := strings.ToLower(strings.ReplaceAll(filepath.Join(os.Getenv("WINDIR"), `System32\drivers`), "/", `\`))
	return strings.HasSuffix(pathValue, ".sys") && !strings.HasPrefix(pathValue, systemRoot)
}

func commandUsesScriptOrLolbin(command string) bool {
	for _, marker := range []string{"powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", ".bat", ".cmd", ".ps1", ".vbs", ".js"} {
		if strings.Contains(command, marker) {
			return true
		}
	}
	return false
}

func looksLikeWindowsMaintenanceName(name string) bool {
	name = strings.ToLower(name)
	return strings.Contains(name, "windows update") ||
		strings.Contains(name, "microsoft update") ||
		strings.Contains(name, "system update") ||
		strings.Contains(name, "security update")
}

func intFromAnyDefault(value any, fallback int) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		return fallback
	}
}

func fnv32(value string) uint32 {
	var hash uint32 = 2166136261
	for _, b := range []byte(value) {
		hash ^= uint32(b)
		hash *= 16777619
	}
	return hash
}
