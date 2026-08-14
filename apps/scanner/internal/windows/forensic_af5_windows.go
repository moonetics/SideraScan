//go:build windows

package windows

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
	"github.com/moonetics/SideraScan/apps/scanner/internal/privacy"
)

const (
	af5ScopedRootLimit      = 100
	af5PowerShellLineLimit  = 80
	af5PowerShellMaxLineLen = 400
)

type forensicAF5Result struct {
	ExecutionArtifacts []map[string]any
	FileLogs           []contract.FileLog
	Evidence           []contract.Evidence
	Findings           []contract.Finding
	Summary            map[string]any
	Warnings           []string
}

type af5Artifact struct {
	ArtifactType string
	Action       string
	Name         string
	Path         string
	Timestamp    time.Time
	Source       string
	Confidence   int
	Status       string
	Severity     string
	Flags        []string
	Metadata     map[string]any
}

func collectExecutionArtifacts(ctx context.Context, options BaselineOptions) forensicAF5Result {
	_ = ctx
	result := forensicAF5Result{}
	reviewMode := forensicReviewMode(options.AdvancedForensics)
	rowLimit := options.AdvancedForensics.MaxRowsPerModule
	if rowLimit <= 0 {
		rowLimit = 500
	}

	artifacts := []map[string]any{}
	fileLogs := []contract.FileLog{}

	prefetchRows, prefetchLogs, prefetchWarnings := collectAF5Prefetch()
	artifacts = append(artifacts, prefetchRows...)
	fileLogs = append(fileLogs, prefetchLogs...)
	result.Warnings = append(result.Warnings, prefetchWarnings...)

	appcompatRows, appcompatWarnings := collectAF5AppCompatMetadata()
	artifacts = append(artifacts, appcompatRows...)
	result.Warnings = append(result.Warnings, appcompatWarnings...)

	recentRows, recentLogs, recentWarnings := collectAF5RecentAndJumpLists()
	artifacts = append(artifacts, recentRows...)
	fileLogs = append(fileLogs, recentLogs...)
	result.Warnings = append(result.Warnings, recentWarnings...)

	recycleRows, recycleLogs, recycleWarnings := collectAF5RecycleBin()
	artifacts = append(artifacts, recycleRows...)
	fileLogs = append(fileLogs, recycleLogs...)
	result.Warnings = append(result.Warnings, recycleWarnings...)

	scopedRows, scopedLogs, scopedWarnings := collectAF5ScopedFolderMetadata()
	artifacts = append(artifacts, scopedRows...)
	fileLogs = append(fileLogs, scopedLogs...)
	result.Warnings = append(result.Warnings, scopedWarnings...)

	psRows, psWarnings := collectAF5PowerShellHistory()
	artifacts = append(artifacts, psRows...)
	result.Warnings = append(result.Warnings, psWarnings...)

	result.ExecutionArtifacts = filterAF5Rows(artifacts, reviewMode, rowLimit)
	result.FileLogs = filterAF5FileLogs(fileLogs, reviewMode, rowLimit)
	for _, row := range result.ExecutionArtifacts {
		if shouldCreateAF5Finding(row) {
			evidence, finding := buildAF5EvidenceFinding(row)
			result.Evidence = append(result.Evidence, evidence)
			result.Findings = append(result.Findings, finding)
		}
	}

	result.Summary = map[string]any{
		"reviewMode":          reviewMode,
		"total":               len(artifacts),
		"uploaded":            len(result.ExecutionArtifacts),
		"sourceCounts":        countStringField(artifacts, "source"),
		"statusCounts":        countStringField(artifacts, "status"),
		"bestEffortWarnings":  uniqueStringsSorted(result.Warnings),
		"metadataSafeMVP":     true,
		"deepHiveParsing":     false,
		"browserHistoryRead":  false,
		"chatContentRead":     false,
		"fileContentUploaded": false,
	}
	return result
}

func collectAF5Prefetch() ([]map[string]any, []contract.FileLog, []string) {
	prefetch := filepath.Join(os.Getenv("SystemRoot"), "Prefetch")
	if strings.TrimSpace(os.Getenv("SystemRoot")) == "" {
		prefetch = `C:\Windows\Prefetch`
	}
	entries, err := os.ReadDir(prefetch)
	if err != nil {
		return nil, nil, []string{"af5_prefetch_unavailable"}
	}
	rows := []map[string]any{}
	logs := []contract.FileLog{}
	count := 0
	for _, entry := range entries {
		if count >= af5ScopedRootLimit {
			break
		}
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".pf") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		path := filepath.Join(prefetch, entry.Name())
		processName := relatedProcessFromPrefetchName(entry.Name())
		flags := af5FlagsForPath(processName, path)
		status := af5StatusForPath(processName, path)
		severity := af5SeverityForStatus(status)
		if policyIsDefenderUpdateArtifact(processName, path) || (status == "review" && !containsString(flags, "windows_like_name_outside_windows")) {
			status = "context"
			severity = "INFO"
			flags = append(flags, "historical_artifact_context")
			if policyIsDefenderUpdateArtifact(processName, path) {
				flags = append(flags, "benign_defender_update_artifact")
			}
			flags = uniqueStringsSorted(flags)
		}
		row := executionArtifactRow(af5Artifact{
			ArtifactType: "prefetch",
			Action:       "executed_file",
			Name:         processName,
			Path:         path,
			Timestamp:    info.ModTime(),
			Source:       "windows_prefetch_metadata",
			Confidence:   65,
			Status:       status,
			Severity:     severity,
			Flags:        flags,
			Metadata:     map[string]any{"metadataOnly": true, "prefetchFile": entry.Name()},
		})
		rows = append(rows, row)
		logs = append(logs, af5FileLogFromRow(row, "executed_file"))
		count++
	}
	return rows, logs, nil
}

func collectAF5AppCompatMetadata() ([]map[string]any, []string) {
	rows := []map[string]any{}
	warnings := []string{}

	amcache := filepath.Join(os.Getenv("SystemRoot"), `AppCompat\Programs\Amcache.hve`)
	if info, err := os.Stat(amcache); err == nil && !info.IsDir() {
		rows = append(rows, executionArtifactRow(af5Artifact{
			ArtifactType: "amcache",
			Action:       "metadata_available",
			Name:         "Amcache.hve",
			Path:         amcache,
			Timestamp:    info.ModTime(),
			Source:       "amcache_file_metadata",
			Confidence:   35,
			Status:       "normal",
			Severity:     "INFO",
			Metadata: map[string]any{
				"metadataOnly":     true,
				"deepHiveParsing":  false,
				"size":             info.Size(),
				"parserLimitation": "AF-5 MVP detects Amcache presence and timestamp only.",
			},
		}))
	} else {
		warnings = append(warnings, "af5_amcache_file_unavailable")
	}

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`, registry.QUERY_VALUE)
	if err != nil {
		warnings = append(warnings, "af5_shimcache_key_unavailable")
		return rows, warnings
	}
	defer key.Close()
	info, err := key.Stat()
	if err != nil {
		warnings = append(warnings, "af5_shimcache_key_stat_unavailable")
		return rows, warnings
	}
	rows = append(rows, executionArtifactRow(af5Artifact{
		ArtifactType: "shimcache",
		Action:       "metadata_available",
		Name:         "AppCompatCache",
		Path:         `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`,
		Timestamp:    info.ModTime(),
		Source:       "shimcache_registry_metadata",
		Confidence:   30,
		Status:       "normal",
		Severity:     "INFO",
		Metadata: map[string]any{
			"metadataOnly":     true,
			"rawValueUploaded": false,
			"deepParsing":      false,
			"parserLimitation": "AF-5 MVP does not upload or parse raw AppCompatCache binary values.",
		},
	}))
	return rows, warnings
}

func collectAF5RecentAndJumpLists() ([]map[string]any, []contract.FileLog, []string) {
	roots := []struct {
		artifactType string
		source       string
		path         string
		extensions   []string
	}{
		{"recent_file", "windows_recent_metadata", filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Recent`), []string{".lnk"}},
		{"jump_list", "windows_jump_list_metadata", filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Recent\AutomaticDestinations`), []string{".automaticdestinations-ms"}},
		{"jump_list", "windows_jump_list_metadata", filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Recent\CustomDestinations`), []string{".customdestinations-ms"}},
	}
	rows := []map[string]any{}
	logs := []contract.FileLog{}
	warnings := []string{}
	for _, root := range roots {
		nextRows, nextLogs, err := collectAF5DirectoryEntries(root.path, root.artifactType, "data_change", root.source, root.extensions, 55, 1)
		if err != nil {
			warnings = append(warnings, "af5_"+safeKey(root.artifactType)+"_unavailable")
			continue
		}
		rows = append(rows, nextRows...)
		logs = append(logs, nextLogs...)
	}
	return rows, logs, warnings
}

func collectAF5RecycleBin() ([]map[string]any, []contract.FileLog, []string) {
	root := filepath.Join(filepath.VolumeName(os.Getenv("SystemDrive")+`\`), `$Recycle.Bin`)
	if strings.TrimSpace(os.Getenv("SystemDrive")) != "" {
		root = filepath.Join(os.Getenv("SystemDrive")+`\`, `$Recycle.Bin`)
	}
	sidDirs, err := os.ReadDir(root)
	if err != nil {
		return nil, nil, []string{"af5_recycle_bin_unavailable"}
	}
	rows := []map[string]any{}
	logs := []contract.FileLog{}
	for _, sidDir := range sidDirs {
		if len(rows) >= af5ScopedRootLimit {
			break
		}
		if !sidDir.IsDir() {
			continue
		}
		dirPath := filepath.Join(root, sidDir.Name())
		entries, err := os.ReadDir(dirPath)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if len(rows) >= af5ScopedRootLimit {
				break
			}
			if entry.IsDir() || strings.HasPrefix(entry.Name(), "$I") {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			path := filepath.Join(dirPath, entry.Name())
			row := executionArtifactRow(af5Artifact{
				ArtifactType: "recycle_bin",
				Action:       "deleted_file",
				Name:         entry.Name(),
				Path:         path,
				Timestamp:    info.ModTime(),
				Source:       "recycle_bin_metadata",
				Confidence:   45,
				Status:       af5StatusForPath(entry.Name(), path),
				Severity:     af5SeverityForStatus(af5StatusForPath(entry.Name(), path)),
				Flags:        append(af5FlagsForPath(entry.Name(), path), "deleted_artifact"),
				Metadata:     map[string]any{"metadataOnly": true, "originalPathParsed": false},
			})
			rows = append(rows, row)
			logs = append(logs, af5FileLogFromRow(row, "deleted_file"))
		}
	}
	return rows, logs, nil
}

func collectAF5ScopedFolderMetadata() ([]map[string]any, []contract.FileLog, []string) {
	roots := []struct {
		artifactType string
		action       string
		source       string
		path         string
		depth        int
	}{
		{"downloads_metadata", "downloaded_file", "downloads_metadata_capped", filepath.Join(os.Getenv("USERPROFILE"), "Downloads"), 1},
		{"temp_metadata", "data_change", "temp_metadata_capped", os.TempDir(), 2},
		{"local_appdata_metadata", "data_change", "local_appdata_metadata_capped", os.Getenv("LOCALAPPDATA"), 1},
		{"roaming_appdata_metadata", "data_change", "roaming_appdata_metadata_capped", os.Getenv("APPDATA"), 1},
	}
	rows := []map[string]any{}
	logs := []contract.FileLog{}
	warnings := []string{}
	for _, root := range roots {
		nextRows, nextLogs, err := collectAF5DirectoryEntries(root.path, root.artifactType, root.action, root.source, suspiciousArtifactExtensions(), 60, root.depth)
		if err != nil {
			warnings = append(warnings, "af5_"+safeKey(root.artifactType)+"_unavailable")
			continue
		}
		rows = append(rows, nextRows...)
		logs = append(logs, nextLogs...)
	}
	return rows, logs, warnings
}

func collectAF5DirectoryEntries(root string, artifactType string, action string, source string, extensions []string, confidence int, maxDepth int) ([]map[string]any, []contract.FileLog, error) {
	if strings.TrimSpace(root) == "" {
		return nil, nil, os.ErrNotExist
	}
	if _, err := os.Stat(root); err != nil {
		return nil, nil, err
	}
	rows := []map[string]any{}
	logs := []contract.FileLog{}
	root = filepath.Clean(root)
	errStop := fmt.Errorf("af5 row cap reached")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if path == root {
			return nil
		}
		depth := pathDepth(root, path)
		if entry.IsDir() {
			if depth > maxDepth {
				return filepath.SkipDir
			}
			if isBlockedContentFolder(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if depth > maxDepth {
			return nil
		}
		if len(rows) >= af5ScopedRootLimit {
			return errStop
		}
		if !hasAnyExtension(entry.Name(), extensions) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		status := af5StatusForPath(entry.Name(), path)
		row := executionArtifactRow(af5Artifact{
			ArtifactType: artifactType,
			Action:       action,
			Name:         entry.Name(),
			Path:         path,
			Timestamp:    info.ModTime(),
			Source:       source,
			Confidence:   confidence,
			Status:       status,
			Severity:     af5SeverityForStatus(status),
			Flags:        af5FlagsForPath(entry.Name(), path),
			Metadata: map[string]any{
				"metadataOnly": true,
				"size":         info.Size(),
				"cappedRoot":   true,
				"maxDepth":     maxDepth,
			},
		})
		rows = append(rows, row)
		logs = append(logs, af5FileLogFromRow(row, action))
		return nil
	})
	if err != nil && err != errStop {
		return rows, logs, err
	}
	return rows, logs, nil
}

func collectAF5PowerShellHistory() ([]map[string]any, []string) {
	historyFiles := []string{}
	if appData := os.Getenv("APPDATA"); appData != "" {
		matches, _ := filepath.Glob(filepath.Join(appData, `Microsoft\Windows\PowerShell\PSReadLine\*_history.txt`))
		historyFiles = append(historyFiles, matches...)
	}
	if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
		matches, _ := filepath.Glob(filepath.Join(userProfile, `Documents\PowerShell\PSReadLine\*_history.txt`))
		historyFiles = append(historyFiles, matches...)
	}
	rows := []map[string]any{}
	warnings := []string{}
	for _, historyPath := range uniqueStringsSorted(historyFiles) {
		file, err := os.Open(historyPath)
		if err != nil {
			warnings = append(warnings, "af5_powershell_history_unavailable")
			continue
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 1024), af5PowerShellMaxLineLen*2)
		lineNumber := 0
		for scanner.Scan() {
			if len(rows) >= af5PowerShellLineLimit {
				break
			}
			lineNumber++
			command := strings.TrimSpace(scanner.Text())
			if !isRelevantPowerShellHistory(command) {
				continue
			}
			if len(command) > af5PowerShellMaxLineLen {
				command = command[:af5PowerShellMaxLineLen]
			}
			redactedCommand := redactCommandLine(command)
			flags := powerShellHistoryFlags(command)
			status := "review"
			severity := "INFO"
			if containsString(flags, "powershell_encoded_command") || containsString(flags, "powershell_download_execute") {
				status = "suspicious"
				severity = "WARNING"
			}
			rows = append(rows, privacy.RedactMap(map[string]any{
				"artifactType":     "powershell_history",
				"action":           "command_observed",
				"name":             filepath.Base(historyPath),
				"command":          redactedCommand,
				"path":             privacy.MaskPath(historyPath),
				"timestamp":        "",
				"source":           "powershell_history_redacted",
				"confidence":       72,
				"status":           status,
				"severity":         severity,
				"suspiciousFlags":  flags,
				"rawCommandStored": false,
				"metadata": map[string]any{
					"lineNumber":        lineNumber,
					"historyFileMasked": privacy.MaskPath(historyPath),
					"redactedOnly":      true,
				},
			}))
		}
		if err := scanner.Err(); err != nil {
			warnings = append(warnings, "af5_powershell_history_read_limited")
		}
		_ = file.Close()
	}
	return rows, warnings
}

func executionArtifactRow(artifact af5Artifact) map[string]any {
	status := firstNonEmptyString(artifact.Status, "normal")
	severity := firstNonEmptyString(artifact.Severity, af5SeverityForStatus(status))
	timestamp := ""
	if !artifact.Timestamp.IsZero() {
		timestamp = artifact.Timestamp.UTC().Format(time.RFC3339)
	}
	return privacy.RedactMap(map[string]any{
		"artifactType":    artifact.ArtifactType,
		"action":          artifact.Action,
		"name":            artifact.Name,
		"path":            privacy.MaskPath(artifact.Path),
		"timestamp":       timestamp,
		"source":          artifact.Source,
		"confidence":      artifact.Confidence,
		"status":          status,
		"severity":        severity,
		"suspiciousFlags": uniqueStringsSorted(artifact.Flags),
		"fileContentRead": false,
		"contentUploaded": false,
		"browserDataRead": false,
		"chatContentRead": false,
		"metadata":        privacy.RedactMap(artifact.Metadata),
	})
}

func filterAF5Rows(rows []map[string]any, reviewMode string, limit int) []map[string]any {
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

func filterAF5FileLogs(logs []contract.FileLog, reviewMode string, limit int) []contract.FileLog {
	filtered := []contract.FileLog{}
	for _, log := range logs {
		if reviewMode == "ai_assisted_full" || log.Severity == "WARNING" || log.Severity == "SEVERE" || log.Severity == "CRITICAL" {
			filtered = append(filtered, log)
		}
		if limit > 0 && len(filtered) >= limit {
			break
		}
	}
	return filtered
}

func shouldCreateAF5Finding(row map[string]any) bool {
	status := strings.ToLower(stringFromAny(row["status"]))
	severity := strings.ToUpper(stringFromAny(row["severity"]))
	return policyShouldCreateFinding(status, severity, stringsFromUnknown(row["suspiciousFlags"]), "")
}

func buildAF5EvidenceFinding(row map[string]any) (contract.Evidence, contract.Finding) {
	title := firstNonEmptyString(stringFromAny(row["name"]), stringFromAny(row["artifactType"]), "Execution artifact")
	artifactType := firstNonEmptyString(stringFromAny(row["artifactType"]), "execution_artifact")
	evidenceID := fmt.Sprintf("af5-%s-%x", artifactType, fnv32(title+stringFromAny(row["path"])+stringFromAny(row["command"])))
	severity := firstNonEmptyString(stringFromAny(row["severity"]), "WARNING")
	evidence := contract.Evidence{
		ClientEvidenceID: evidenceID,
		Type:             artifactType,
		Title:            "Execution artifact: " + title,
		Data:             privacy.RedactMap(row),
	}
	finding := contract.Finding{
		Category:     "FILE",
		Severity:     severity,
		Title:        "Execution artifact requires review: " + title,
		Message:      "A historical execution or file usage artifact matched forensic review heuristics.",
		EvidenceRef:  evidenceID,
		Confidence:   intFromAnyDefault(row["confidence"], 70),
		SourceModule: "execution_artifacts",
		Metadata: privacy.RedactMap(map[string]any{
			"artifactType":    artifactType,
			"action":          row["action"],
			"path":            row["path"],
			"status":          row["status"],
			"suspiciousFlags": row["suspiciousFlags"],
		}),
	}
	return evidence, finding
}

func af5FileLogFromRow(row map[string]any, action string) contract.FileLog {
	severity := firstNonEmptyString(stringFromAny(row["severity"]), "INFO")
	timestamp := stringFromAny(row["timestamp"])
	return contract.FileLog{
		Action:         firstNonEmptyString(action, stringFromAny(row["action"]), "unknown"),
		Path:           stringFromAny(row["path"]),
		Timestamp:      timestamp,
		Source:         firstNonEmptyString(stringFromAny(row["source"]), "execution_artifacts"),
		Confidence:     intFromAnyDefault(row["confidence"], 50),
		RelatedProcess: stringFromAny(row["name"]),
		Severity:       severity,
		Metadata: privacy.RedactMap(map[string]any{
			"artifactType":    row["artifactType"],
			"metadataOnly":    true,
			"fileContentRead": false,
			"contentUploaded": false,
			"suspiciousFlags": row["suspiciousFlags"],
		}),
	}
}

func af5StatusForPath(name string, path string) string {
	flags := af5FlagsForPath(name, path)
	if containsString(flags, "powershell_encoded_command") ||
		containsString(flags, "powershell_download_execute") ||
		containsString(flags, "windows_like_name_outside_windows") {
		return "suspicious"
	}
	if len(flags) > 0 {
		return "review"
	}
	return "normal"
}

func af5SeverityForStatus(status string) string {
	switch strings.ToLower(status) {
	case "suspicious", "flagged":
		return "WARNING"
	case "review":
		return "INFO"
	default:
		return "INFO"
	}
}

func af5FlagsForPath(name string, path string) []string {
	flags := []string{}
	lowerPath := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	lowerName := strings.ToLower(name)
	extension := strings.ToLower(filepath.Ext(name))
	if isRiskyExecutionExtension(extension) {
		flags = append(flags, "executable_or_script_artifact")
	}
	if isUserWritablePath(lowerPath) && isRiskyExecutionExtension(extension) {
		flags = append(flags, "user_writable_executable")
	}
	if strings.Contains(lowerPath, `\downloads`) && isRiskyExecutionExtension(extension) {
		flags = append(flags, "downloads_executable")
	}
	if strings.Contains(lowerPath, `\temp`) && isRiskyExecutionExtension(extension) {
		flags = append(flags, "temp_executable")
	}
	if looksLikeWindowsSystemName(lowerName) && !strings.Contains(lowerPath, `\windows\`) {
		flags = append(flags, "windows_like_name_outside_windows")
	}
	if looksRandomFileName(strings.TrimSuffix(lowerName, extension)) && isRiskyExecutionExtension(extension) {
		flags = append(flags, "random_like_filename")
	}
	return uniqueStringsSorted(flags)
}

func isRelevantPowerShellHistory(command string) bool {
	command = strings.ToLower(command)
	for _, marker := range []string{"invoke-webrequest", "iwr ", "curl ", "wget ", "downloadstring", "downloadfile", "frombase64string", "-enc", "-encodedcommand", "start-process", "iex", "invoke-expression", ".exe", ".dll", ".ps1", "roblox", "bloxstrap", "inject", "loader", "cheat"} {
		if strings.Contains(command, marker) {
			return true
		}
	}
	return false
}

func powerShellHistoryFlags(command string) []string {
	lower := strings.ToLower(command)
	flags := []string{"powershell_history_relevant"}
	if strings.Contains(lower, "-enc") || strings.Contains(lower, "-encodedcommand") || strings.Contains(lower, "frombase64string") {
		flags = append(flags, "powershell_encoded_command")
	}
	if strings.Contains(lower, "downloadstring") || strings.Contains(lower, "downloadfile") || strings.Contains(lower, "invoke-webrequest") || strings.Contains(lower, "iwr ") || strings.Contains(lower, "curl ") || strings.Contains(lower, "wget ") {
		flags = append(flags, "powershell_download_execute")
	}
	if strings.Contains(lower, "iex") || strings.Contains(lower, "invoke-expression") {
		flags = append(flags, "powershell_invoke_expression")
	}
	if strings.Contains(lower, "roblox") || strings.Contains(lower, "bloxstrap") {
		flags = append(flags, "roblox_related_command")
	}
	return uniqueStringsSorted(flags)
}

func relatedProcessFromPrefetchName(name string) string {
	base := strings.TrimSuffix(name, filepath.Ext(name))
	if index := strings.LastIndex(base, "-"); index > 0 {
		base = base[:index]
	}
	if !strings.HasSuffix(strings.ToLower(base), ".exe") {
		base += ".exe"
	}
	return base
}

func suspiciousArtifactExtensions() []string {
	return []string{".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jar", ".zip", ".rar", ".7z"}
}

func isRiskyExecutionExtension(extension string) bool {
	switch strings.ToLower(extension) {
	case ".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jar":
		return true
	default:
		return false
	}
}

func hasAnyExtension(name string, extensions []string) bool {
	extension := strings.ToLower(filepath.Ext(name))
	for _, allowed := range extensions {
		if extension == strings.ToLower(allowed) {
			return true
		}
	}
	return false
}

func isBlockedContentFolder(name string) bool {
	lower := strings.ToLower(name)
	return lower == "cookies" ||
		lower == "history" ||
		lower == "cache" ||
		lower == "discord" ||
		lower == "telegram desktop" ||
		lower == "chrome" ||
		lower == "edge" ||
		lower == "firefox" ||
		lower == "brave-browser"
}

func pathDepth(root string, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return af5ScopedRootLimit
	}
	if rel == "." {
		return 0
	}
	return len(strings.Split(rel, string(filepath.Separator)))
}

func looksLikeWindowsSystemName(name string) bool {
	switch strings.ToLower(name) {
	case "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "spoolsv.exe", "taskhostw.exe", "rundll32.exe", "regsvr32.exe", "powershell.exe", "cmd.exe":
		return true
	default:
		return false
	}
}

func looksRandomFileName(name string) bool {
	name = strings.TrimSpace(name)
	if len(name) < 8 || len(name) > 18 {
		return false
	}
	letters := 0
	digits := 0
	hexish := 0
	for _, char := range name {
		if char >= 'a' && char <= 'f' || char >= 'A' && char <= 'F' || char >= '0' && char <= '9' {
			hexish++
		}
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' {
			letters++
		}
		if char >= '0' && char <= '9' {
			digits++
		}
	}
	return hexish == len(name) && letters > 0 && digits > 0
}

func decodeUTF16String(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	values := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		value := uint16(data[i]) | uint16(data[i+1])<<8
		if value == 0 {
			break
		}
		values = append(values, value)
	}
	return string(utf16.Decode(values))
}

func countStringField(rows []map[string]any, key string) map[string]int {
	counts := map[string]int{}
	for _, row := range rows {
		value := firstNonEmptyString(stringFromAny(row[key]), "unknown")
		counts[value]++
	}
	return counts
}
