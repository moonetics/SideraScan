//go:build windows

package windows

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	gopsprocess "github.com/shirou/gopsutil/v4/process"
	winapi "golang.org/x/sys/windows"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
	"github.com/moonetics/SideraScan/apps/scanner/internal/privacy"
)

const (
	systemExtendedHandleInformation = 64
	maxSystemHandlesToInspect       = 120000
)

type forensicAF2Result struct {
	LoadedModules  []map[string]any
	ProcessHandles []map[string]any
	Evidence       []contract.Evidence
	Findings       []contract.Finding
	Warnings       []string
}

type forensicTarget struct {
	ProcessName string
	PID         int32
	RawPath     string
	Source      string
}

type systemHandleTableEntryInfoEx struct {
	Object                uintptr
	UniqueProcessID       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

type loadedModuleRecord struct {
	Target      forensicTarget
	ModuleName  string
	RawPath     string
	BaseAddress string
	Index       int
}

type processHandleRecord struct {
	Target        forensicTarget
	SourcePID     int32
	HandleValue   uintptr
	AccessMask    uint32
	SourceName    string
	SourceRawPath string
}

func collectGameProcessForensics(ctx context.Context, processTimeline []map[string]any, options BaselineOptions, signatureCache map[string]signatureInfo) forensicAF2Result {
	result := forensicAF2Result{}
	targets := selectForensicTargets(processTimeline, options.Rules)
	if len(targets) == 0 {
		return result
	}

	rowLimit := options.AdvancedForensics.MaxRowsPerModule
	if rowLimit <= 0 {
		rowLimit = 500
	}
	maxHashMB := options.AdvancedForensics.MaxFileHashMB
	if maxHashMB <= 0 {
		maxHashMB = MaxExecutableHashMB
	}

	for _, target := range targets {
		rows, evidence, findings, warnings := collectLoadedModulesForTarget(ctx, target, rowLimit-len(result.LoadedModules), maxHashMB, signatureCache)
		result.LoadedModules = append(result.LoadedModules, rows...)
		result.Evidence = append(result.Evidence, evidence...)
		result.Findings = append(result.Findings, findings...)
		result.Warnings = append(result.Warnings, warnings...)
		if len(result.LoadedModules) >= rowLimit {
			result.Warnings = append(result.Warnings, "af2_loaded_modules_row_limit")
			break
		}
	}

	handleRows, handleEvidence, handleFindings, handleWarnings := collectHandlesToTargets(ctx, targets, rowLimit, maxHashMB, signatureCache)
	result.ProcessHandles = append(result.ProcessHandles, handleRows...)
	result.Evidence = append(result.Evidence, handleEvidence...)
	result.Findings = append(result.Findings, handleFindings...)
	result.Warnings = append(result.Warnings, handleWarnings...)

	return result
}

func selectForensicTargets(processTimeline []map[string]any, rules []contract.ScannerRule) []forensicTarget {
	targets := []forensicTarget{}
	seen := map[int32]bool{}
	for _, row := range processTimeline {
		pid, ok := int32FromAny(row["pid"])
		if !ok || pid <= 0 || seen[pid] {
			continue
		}
		name := stringFromAny(row["processName"])
		pathValue := stringFromAny(row["path"])
		if isDefaultGameProcess(name) || matchesProcessRule(name, rules) {
			targets = append(targets, forensicTarget{
				ProcessName: firstNonEmptyString(name, "Unknown"),
				PID:         pid,
				RawPath:     pathValue,
				Source:      targetSource(name, rules),
			})
			seen[pid] = true
		}
	}
	return targets
}

func isDefaultGameProcess(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "robloxplayerbeta.exe", "robloxstudiobeta.exe", "robloxcrashhandler.exe":
		return true
	default:
		return false
	}
}

func targetSource(name string, rules []contract.ScannerRule) string {
	if isDefaultGameProcess(name) {
		return "default_roblox_target"
	}
	if matchesProcessRule(name, rules) {
		return "custom_process_rule_target"
	}
	return "unknown_target"
}

func matchesProcessRule(name string, rules []contract.ScannerRule) bool {
	for _, rule := range rules {
		if !strings.EqualFold(rule.Type, "PROCESS_NAME") {
			continue
		}
		processNames := stringsFromConfigAny(rule.RuleConfig["processNames"])
		mode := strings.ToLower(strings.TrimSpace(stringFromAny(rule.RuleConfig["matchMode"])))
		for _, pattern := range processNames {
			if matchRuleText(name, pattern, mode) {
				return true
			}
		}
	}
	return false
}

func collectLoadedModulesForTarget(ctx context.Context, target forensicTarget, remainingRows int, maxHashMB int, signatureCache map[string]signatureInfo) ([]map[string]any, []contract.Evidence, []contract.Finding, []string) {
	if remainingRows <= 0 {
		return nil, nil, nil, nil
	}

	snapshot, err := winapi.CreateToolhelp32Snapshot(winapi.TH32CS_SNAPMODULE|winapi.TH32CS_SNAPMODULE32, uint32(target.PID))
	if err != nil {
		return nil, nil, nil, []string{"af2_loaded_modules_unavailable"}
	}
	defer winapi.CloseHandle(snapshot)

	entry := winapi.ModuleEntry32{Size: uint32(unsafe.Sizeof(winapi.ModuleEntry32{}))}
	if err := winapi.Module32First(snapshot, &entry); err != nil {
		return nil, nil, nil, []string{"af2_loaded_modules_empty"}
	}

	rows := []map[string]any{}
	evidence := []contract.Evidence{}
	findings := []contract.Finding{}
	index := 0
	for {
		record := loadedModuleRecord{
			Target:      target,
			ModuleName:  winapi.UTF16ToString(entry.Module[:]),
			RawPath:     winapi.UTF16ToString(entry.ExePath[:]),
			BaseAddress: fmt.Sprintf("0x%x", entry.ModBaseAddr),
			Index:       index,
		}
		row, ev, finding := loadedModuleRow(ctx, record, maxHashMB, signatureCache)
		rows = append(rows, row)
		if ev != nil {
			evidence = append(evidence, *ev)
		}
		if finding != nil {
			findings = append(findings, *finding)
		}
		if len(rows) >= remainingRows {
			break
		}

		index++
		if err := winapi.Module32Next(snapshot, &entry); err != nil {
			break
		}
	}

	return rows, evidence, findings, nil
}

func loadedModuleRow(ctx context.Context, record loadedModuleRecord, maxHashMB int, signatureCache map[string]signatureInfo) (map[string]any, *contract.Evidence, *contract.Finding) {
	signature := cachedSignature(ctx, record.RawPath, signatureCache)
	flags := suspiciousPathFlags(record.ModuleName, record.RawPath, signature)
	overlay := isKnownLegitOverlay(record.ModuleName, record.RawPath, signature.Publisher)
	benignModule := policyIsOfficialRobloxPath(record.RawPath) ||
		policyIsCommonWindowsDLL(record.ModuleName, record.RawPath, signature.Publisher, signature.Signer) ||
		policyIsKnownVendorArtifact(record.ModuleName, record.RawPath, signature.Publisher, signature.Signer)
	status := "observed"
	severity := "INFO"
	if len(flags) > 0 || signature.Status == "unsigned" {
		status = "review"
		severity = "INFO"
	}
	if overlay || benignModule {
		status = "observed"
		severity = "INFO"
		if overlay {
			flags = append(flags, "known_overlay_review_only")
		}
		if benignModule {
			flags = append(flags, "benign_known_module")
		}
		flags = uniqueStringsSorted(flags)
	}

	confidence := 65
	if status == "review" {
		confidence = 78
	}
	if overlay {
		confidence = 55
	}

	row := map[string]any{
		"targetProcessName": record.Target.ProcessName,
		"targetPid":         record.Target.PID,
		"moduleName":        record.ModuleName,
		"path":              privacy.MaskPath(record.RawPath),
		"signer":            signature.Signer,
		"publisher":         signature.Publisher,
		"signatureStatus":   signature.Status,
		"loadedBaseAddress": record.BaseAddress,
		"createdTime":       fileCreatedTime(record.RawPath),
		"modifiedTime":      fileModifiedTime(record.RawPath),
		"source":            "windows_toolhelp_modules",
		"confidence":        confidence,
		"status":            status,
		"severity":          severity,
		"suspiciousFlags":   flags,
		"limitedReasons":    limitedReasonsFromSignature(signature),
		"hashPolicy":        "suspicious_or_rule_match_only",
		"metadata":          map[string]any{"manualMappedDllLimitation": true, "targetSource": record.Target.Source, "knownLegitOverlay": overlay},
	}

	if policyShouldCreateFinding(status, severity, flags, signature.Status) && !overlay && !benignModule {
		if executableHash, hashStatus := hashExecutableIfAllowedMax(record.RawPath, maxHashMB); hashStatus != "" {
			row["hashStatus"] = hashStatus
			if executableHash != "" {
				row["sha256"] = executableHash
			}
		}
	}

	redacted := privacy.RedactMap(row)
	if policyShouldCreateFinding(status, severity, flags, signature.Status) && !overlay && !benignModule {
		ev, finding := buildLoadedModuleFinding(record, redacted, flags, severity, confidence)
		return redacted, &ev, &finding
	}
	return redacted, nil, nil
}

func collectHandlesToTargets(ctx context.Context, targets []forensicTarget, rowLimit int, maxHashMB int, signatureCache map[string]signatureInfo) ([]map[string]any, []contract.Evidence, []contract.Finding, []string) {
	entries, err := querySystemHandles()
	if err != nil {
		return nil, nil, nil, []string{"af2_process_handles_unavailable"}
	}

	targetByPID := map[uint32]forensicTarget{}
	for _, target := range targets {
		targetByPID[uint32(target.PID)] = target
	}

	rows := []map[string]any{}
	evidence := []contract.Evidence{}
	findings := []contract.Finding{}
	sourceHandles := map[uint32]winapi.Handle{}
	defer func() {
		for _, handle := range sourceHandles {
			_ = winapi.CloseHandle(handle)
		}
	}()

	for index, entry := range entries {
		if index >= maxSystemHandlesToInspect || len(rows) >= rowLimit {
			break
		}
		sourcePID := uint32(entry.UniqueProcessID)
		if sourcePID == 0 {
			continue
		}

		sourceHandle := sourceHandles[sourcePID]
		if sourceHandle == 0 {
			handle, err := winapi.OpenProcess(winapi.PROCESS_DUP_HANDLE|winapi.PROCESS_QUERY_LIMITED_INFORMATION, false, sourcePID)
			if err != nil {
				continue
			}
			sourceHandle = handle
			sourceHandles[sourcePID] = handle
		}

		var duplicated winapi.Handle
		if err := winapi.DuplicateHandle(sourceHandle, winapi.Handle(entry.HandleValue), winapi.CurrentProcess(), &duplicated, 0, false, winapi.DUPLICATE_SAME_ACCESS); err != nil {
			continue
		}
		targetPID, err := winapi.GetProcessId(duplicated)
		_ = winapi.CloseHandle(duplicated)
		if err != nil || targetPID == 0 {
			continue
		}
		target, ok := targetByPID[targetPID]
		if !ok || int32(sourcePID) == target.PID {
			continue
		}

		record := processHandleRecord{
			Target:      target,
			SourcePID:   int32(sourcePID),
			HandleValue: entry.HandleValue,
			AccessMask:  entry.GrantedAccess,
		}
		record.SourceName, record.SourceRawPath = processIdentity(ctx, record.SourcePID)
		row, ev, finding := processHandleRow(ctx, record, maxHashMB, signatureCache)
		rows = append(rows, row)
		if ev != nil {
			evidence = append(evidence, *ev)
		}
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	if len(rows) >= rowLimit {
		return rows, evidence, findings, []string{"af2_process_handles_row_limit"}
	}
	return rows, evidence, findings, nil
}

func processHandleRow(ctx context.Context, record processHandleRecord, maxHashMB int, signatureCache map[string]signatureInfo) (map[string]any, *contract.Evidence, *contract.Finding) {
	signature := cachedSignature(ctx, record.SourceRawPath, signatureCache)
	flags := suspiciousPathFlags(record.SourceName, record.SourceRawPath, signature)
	overlay := isKnownLegitOverlay(record.SourceName, record.SourceRawPath, signature.Publisher)
	benignSource := policyIsKnownVendorArtifact(record.SourceName, record.SourceRawPath, signature.Publisher, signature.Signer) ||
		policyIsCommonWindowsDLL(record.SourceName, record.SourceRawPath, signature.Publisher, signature.Signer)
	accessRights := decodeProcessAccess(record.AccessMask)
	status := "observed"
	severity := "INFO"
	if len(flags) > 0 || hasSensitiveProcessAccess(accessRights) {
		status = "review"
		severity = "INFO"
	}
	if overlay || benignSource {
		status = "observed"
		severity = "INFO"
		if overlay {
			flags = append(flags, "known_overlay_review_only")
		}
		if benignSource {
			flags = append(flags, "benign_known_process_handle_source")
		}
		flags = uniqueStringsSorted(flags)
	}

	confidence := 72
	if status == "review" {
		confidence = 82
	}
	if overlay {
		confidence = 55
	}

	row := map[string]any{
		"targetProcessName": record.Target.ProcessName,
		"targetPid":         record.Target.PID,
		"sourceProcessName": firstNonEmptyString(record.SourceName, "Unknown"),
		"sourcePid":         record.SourcePID,
		"sourcePath":        privacy.MaskPath(record.SourceRawPath),
		"accessMask":        fmt.Sprintf("0x%x", record.AccessMask),
		"accessRights":      accessRights,
		"handleType":        "process",
		"signer":            signature.Signer,
		"publisher":         signature.Publisher,
		"signatureStatus":   signature.Status,
		"source":            "ntquery_system_handles",
		"confidence":        confidence,
		"status":            status,
		"severity":          severity,
		"suspiciousFlags":   flags,
		"limitedReasons":    limitedReasonsFromSignature(signature),
		"hashPolicy":        "suspicious_or_rule_match_only",
		"metadata":          map[string]any{"targetSource": record.Target.Source, "knownLegitOverlay": overlay, "handleValue": fmt.Sprintf("0x%x", record.HandleValue)},
	}

	if policyShouldCreateFinding(status, severity, flags, signature.Status) && !overlay && !benignSource {
		if executableHash, hashStatus := hashExecutableIfAllowedMax(record.SourceRawPath, maxHashMB); hashStatus != "" {
			row["hashStatus"] = hashStatus
			if executableHash != "" {
				row["sha256"] = executableHash
			}
		}
	}

	redacted := privacy.RedactMap(row)
	if policyShouldCreateFinding(status, severity, flags, signature.Status) && !overlay && !benignSource {
		ev, finding := buildProcessHandleFinding(record, redacted, flags, severity, confidence)
		return redacted, &ev, &finding
	}
	return redacted, nil, nil
}

func querySystemHandles() ([]systemHandleTableEntryInfoEx, error) {
	size := uint32(1 << 20)
	for attempt := 0; attempt < 6; attempt++ {
		buffer := make([]byte, size)
		var returned uint32
		err := winapi.NtQuerySystemInformation(systemExtendedHandleInformation, unsafe.Pointer(&buffer[0]), size, &returned)
		if err == nil {
			count := *(*uintptr)(unsafe.Pointer(&buffer[0]))
			if count == 0 {
				return nil, nil
			}
			entrySize := unsafe.Sizeof(systemHandleTableEntryInfoEx{})
			start := uintptr(unsafe.Pointer(&buffer[0])) + unsafe.Sizeof(uintptr(0))*2
			entries := make([]systemHandleTableEntryInfoEx, 0, minInt(int(count), maxSystemHandlesToInspect))
			for index := 0; index < int(count) && index < maxSystemHandlesToInspect; index++ {
				entry := *(*systemHandleTableEntryInfoEx)(unsafe.Pointer(start + uintptr(index)*entrySize))
				entries = append(entries, entry)
			}
			return entries, nil
		}
		if returned > size {
			size = returned + 1<<16
			continue
		}
		size *= 2
	}
	return nil, fmt.Errorf("system handles unavailable")
}

func processIdentity(ctx context.Context, pid int32) (string, string) {
	proc, err := gopsprocess.NewProcessWithContext(ctx, pid)
	if err != nil {
		return "", ""
	}
	name, _ := proc.NameWithContext(ctx)
	path, _ := proc.ExeWithContext(ctx)
	return name, path
}

func cachedSignature(ctx context.Context, rawPath string, cache map[string]signatureInfo) signatureInfo {
	if strings.TrimSpace(rawPath) == "" {
		return signatureInfo{Status: "unknown", Reason: "path_unavailable"}
	}
	if cached, ok := cache[rawPath]; ok {
		return cached
	}
	if len(cache) >= maxSignatureChecksPerScan {
		return signatureInfo{Status: "not_checked", Reason: "signature_check_limit"}
	}
	signature := collectSignatureInfo(ctx, rawPath)
	cache[rawPath] = signature
	return signature
}

func hashExecutableIfAllowedMax(path string, maxHashMB int) (string, string) {
	if maxHashMB <= 0 || maxHashMB == MaxExecutableHashMB {
		return hashExecutableIfAllowed(path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", "file_unavailable"
	}
	if info.IsDir() {
		return "", "not_regular_file"
	}
	if info.Size() > int64(maxHashMB)*1024*1024 {
		return "", "file_too_large"
	}
	return hashExecutableIfAllowed(path)
}

func fileCreatedTime(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if data, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		return time.Unix(0, data.CreationTime.Nanoseconds()).UTC().Format(time.RFC3339)
	}
	return ""
}

func fileModifiedTime(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return info.ModTime().UTC().Format(time.RFC3339)
}

func buildLoadedModuleFinding(record loadedModuleRecord, row map[string]any, flags []string, severity string, confidence int) (contract.Evidence, contract.Finding) {
	evidenceID := fmt.Sprintf("loaded-module-%d-%d", record.Target.PID, record.Index)
	evidence := contract.Evidence{
		ClientEvidenceID: evidenceID,
		Type:             "loaded_module",
		Title:            "Loaded DLL: " + firstNonEmptyString(record.ModuleName, "Unknown"),
		Data:             privacy.RedactMap(row),
	}
	finding := contract.Finding{
		Category:     "PROCESS",
		Severity:     severity,
		Title:        "Loaded DLL requires review: " + firstNonEmptyString(record.ModuleName, "Unknown"),
		Message:      "A DLL loaded inside a game process matched path, signature, or naming review heuristics.",
		EvidenceRef:  evidenceID,
		Confidence:   confidence,
		SourceModule: "loaded_modules",
		Metadata: privacy.RedactMap(map[string]any{
			"targetProcessName": record.Target.ProcessName,
			"targetPid":         record.Target.PID,
			"moduleName":        record.ModuleName,
			"path":              row["path"],
			"suspiciousFlags":   flags,
			"signatureStatus":   row["signatureStatus"],
			"hashPrefix":        shortHashString(row["sha256"]),
		}),
	}
	return evidence, finding
}

func buildProcessHandleFinding(record processHandleRecord, row map[string]any, flags []string, severity string, confidence int) (contract.Evidence, contract.Finding) {
	evidenceID := fmt.Sprintf("process-handle-%d-%d-%x", record.Target.PID, record.SourcePID, record.HandleValue)
	evidence := contract.Evidence{
		ClientEvidenceID: evidenceID,
		Type:             "process_handle",
		Title:            "Process handle to game: " + firstNonEmptyString(record.SourceName, "Unknown"),
		Data:             privacy.RedactMap(row),
	}
	finding := contract.Finding{
		Category:     "PROCESS",
		Severity:     severity,
		Title:        "External process handle requires review: " + firstNonEmptyString(record.SourceName, "Unknown"),
		Message:      "A non-game process holds a handle to the game process with review-worthy access or source metadata.",
		EvidenceRef:  evidenceID,
		Confidence:   confidence,
		SourceModule: "process_handles",
		Metadata: privacy.RedactMap(map[string]any{
			"targetProcessName": record.Target.ProcessName,
			"targetPid":         record.Target.PID,
			"sourceProcessName": record.SourceName,
			"sourcePid":         record.SourcePID,
			"sourcePath":        row["sourcePath"],
			"accessMask":        row["accessMask"],
			"accessRights":      row["accessRights"],
			"suspiciousFlags":   flags,
			"signatureStatus":   row["signatureStatus"],
			"hashPrefix":        shortHashString(row["sha256"]),
		}),
	}
	return evidence, finding
}

func decodeProcessAccess(mask uint32) []string {
	rights := []string{}
	candidates := []struct {
		bit  uint32
		name string
	}{
		{0x0001, "terminate"},
		{0x0002, "create_thread"},
		{0x0008, "vm_operation"},
		{0x0010, "vm_read"},
		{0x0020, "vm_write"},
		{0x0040, "dup_handle"},
		{0x0400, "query_information"},
		{0x0800, "suspend_resume"},
		{0x1000, "query_limited_information"},
		{0x00100000, "synchronize"},
	}
	for _, candidate := range candidates {
		if mask&candidate.bit != 0 {
			rights = append(rights, candidate.name)
		}
	}
	return rights
}

func hasSensitiveProcessAccess(rights []string) bool {
	for _, right := range rights {
		switch right {
		case "create_thread", "vm_operation", "vm_read", "vm_write", "dup_handle", "suspend_resume":
			return true
		}
	}
	return false
}

func limitedReasonsFromSignature(signature signatureInfo) []string {
	if signature.Reason == "" {
		return nil
	}
	return []string{signature.Reason}
}

func isKnownLegitOverlay(name string, pathValue string, publisher string) bool {
	value := strings.ToLower(name + " " + pathValue + " " + publisher)
	known := []string{
		"discordhook",
		"gameoverlayrenderer",
		"steam",
		"nvidia",
		"nvspcap",
		"amd",
		"obs",
		"graphics-hook",
		"msi afterburner",
		"rtsshooks",
		"rivatuner",
		"overwolf",
	}
	for _, item := range known {
		if strings.Contains(value, item) {
			return true
		}
	}
	return false
}

func matchRuleText(value string, pattern string, mode string) bool {
	value = strings.TrimSpace(value)
	pattern = strings.TrimSpace(pattern)
	if value == "" || pattern == "" {
		return false
	}
	switch mode {
	case "exact":
		return strings.EqualFold(value, pattern)
	case "regex":
		compiled, err := regexp.Compile(pattern)
		return err == nil && compiled.MatchString(value)
	case "contains", "":
		return strings.Contains(strings.ToLower(value), strings.ToLower(pattern))
	default:
		return false
	}
}

func stringsFromConfigAny(value any) []string {
	items := []string{}
	switch typed := value.(type) {
	case []string:
		items = append(items, typed...)
	case []any:
		for _, item := range typed {
			if text := stringFromAny(item); text != "" {
				items = append(items, text)
			}
		}
	}
	return items
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return ""
	}
}

func int32FromAny(value any) (int32, bool) {
	switch typed := value.(type) {
	case int32:
		return typed, true
	case int:
		return int32(typed), true
	case int64:
		return int32(typed), true
	case float64:
		return int32(typed), true
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 32)
		return int32(parsed), err == nil
	default:
		return 0, false
	}
}

func modulePathFlagsForTest(name string, pathValue string, status string) []string {
	return suspiciousPathFlags(name, pathValue, signatureInfo{Status: status})
}

func cleanModulePathForTest(pathValue string) string {
	return privacy.MaskPath(filepath.Clean(pathValue))
}
