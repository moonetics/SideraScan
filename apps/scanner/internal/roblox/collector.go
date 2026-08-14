package roblox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
	"github.com/moonetics/SideraScan/apps/scanner/internal/privacy"
)

const (
	MaxWalkFiles        = 500
	MaxDownloadRows     = 60
	MaxPrefetchRows     = 40
	MaxLauncherHashMB   = 100
	collectorSource     = "roblox_baseline"
	defaultInfoSeverity = "INFO"
)

type Options struct {
	StartedAt       time.Time
	Now             time.Time
	LocalAppData    string
	UserProfile     string
	ProcessTimeline []map[string]any
}

type Snapshot struct {
	LauncherProfiles     []contract.LauncherProfile
	ClientModAssets      []contract.ClientModAsset
	ProcessTimes         []contract.ProcessTime
	FileLogs             []contract.FileLog
	StringCandidateFiles []string
	PartialErrors        []string
}

type roots struct {
	localAppData string
	userProfile  string
	robloxRoot   string
	versionsRoot string
	bloxstrap    []string
	downloads    string
	prefetch     string
}

func Collect(ctx context.Context, options Options) Snapshot {
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	roots := resolveRoots(options)
	snapshot := Snapshot{}
	partials := []string{}

	profiles, profileLogs, profileCandidates, err := collectLauncherProfiles(ctx, roots, options.ProcessTimeline)
	if err != nil {
		partials = append(partials, "launcher_profiles")
	}
	snapshot.LauncherProfiles = profiles
	snapshot.FileLogs = append(snapshot.FileLogs, profileLogs...)
	snapshot.StringCandidateFiles = append(snapshot.StringCandidateFiles, profileCandidates...)

	assets, assetLogs, candidateFiles, err := collectClientModAssets(ctx, roots)
	if err != nil {
		partials = append(partials, "client_mod_assets")
	}
	snapshot.ClientModAssets = assets
	snapshot.FileLogs = append(snapshot.FileLogs, assetLogs...)
	snapshot.StringCandidateFiles = append(snapshot.StringCandidateFiles, candidateFiles...)

	snapshot.ProcessTimes = collectProcessTimes(options.ProcessTimeline, now)
	snapshot.FileLogs = append(snapshot.FileLogs, liveProcessFileLogs(options.ProcessTimeline, now)...)

	fileLogs, err := collectExploreFileLogs(ctx, roots)
	if err != nil {
		partials = append(partials, "explore_file_logs")
	}
	snapshot.FileLogs = append(snapshot.FileLogs, fileLogs...)

	snapshot.PartialErrors = partials
	return snapshot
}

func liveProcessFileLogs(processTimeline []map[string]any, now time.Time) []contract.FileLog {
	logs := []contract.FileLog{}
	for _, process := range processTimeline {
		name := stringValue(process, "processName")
		if !isRobloxProcess(name) {
			continue
		}
		timestamp := now
		if startedAt := stringValue(process, "startTime"); startedAt != "" {
			if parsed, err := time.Parse(time.RFC3339, startedAt); err == nil && !parsed.IsZero() {
				timestamp = parsed
			}
		}
		logs = append(logs, fileLog(
			"executed_file",
			stringValue(process, "path"),
			"",
			"",
			timestamp,
			"live_process",
			85,
			name,
			defaultInfoSeverity,
			map[string]any{
				"pid":             process["pid"],
				"observedAt":      now.UTC().Format(time.RFC3339),
				"liveProcessOnly": true,
			},
		))
	}
	return logs
}

func resolveRoots(options Options) roots {
	localAppData := firstNonEmpty(options.LocalAppData, os.Getenv("LOCALAPPDATA"))
	userProfile := firstNonEmpty(options.UserProfile, os.Getenv("USERPROFILE"))
	if userProfile == "" {
		userProfile, _ = os.UserHomeDir()
	}

	bloxstrapRoots := []string{}
	if localAppData != "" {
		bloxstrapRoots = append(bloxstrapRoots,
			filepath.Join(localAppData, "Bloxstrap"),
			filepath.Join(localAppData, "Programs", "Bloxstrap"),
		)
	}

	prefetch := filepath.Join(os.Getenv("SystemRoot"), "Prefetch")
	if os.Getenv("SystemRoot") == "" {
		prefetch = `C:\Windows\Prefetch`
	}

	return roots{
		localAppData: localAppData,
		userProfile:  userProfile,
		robloxRoot:   filepath.Join(localAppData, "Roblox"),
		versionsRoot: filepath.Join(localAppData, "Roblox", "Versions"),
		bloxstrap:    bloxstrapRoots,
		downloads:    filepath.Join(userProfile, "Downloads"),
		prefetch:     prefetch,
	}
}

func collectLauncherProfiles(ctx context.Context, roots roots, processTimeline []map[string]any) ([]contract.LauncherProfile, []contract.FileLog, []string, error) {
	_ = ctx
	profiles := []contract.LauncherProfile{}
	logs := []contract.FileLog{}
	candidateFiles := []string{}
	seen := map[string]bool{}
	errs := []string{}

	matches, err := filepath.Glob(filepath.Join(roots.versionsRoot, "*", "RobloxPlayerBeta.exe"))
	if err != nil {
		errs = append(errs, "official_glob")
	}
	for _, executable := range matches {
		if seen[normalizePath(executable)] {
			continue
		}
		seen[normalizePath(executable)] = true
		info, _ := os.Stat(executable)
		version := filepath.Base(filepath.Dir(executable))
		status := "inactive"
		lastLaunch := ""
		if process := findProcess(processTimeline, "RobloxPlayerBeta.exe"); process != nil {
			status = "active"
			lastLaunch = stringValue(process, "startTime")
		}
		profiles = append(profiles, launcherProfile("RobloxPlayerBeta", "official_roblox", version, "production", executable, status, []string{"official"}, info, lastLaunch))
		logs = append(logs, fileLog("executed_file", executable, "", "", timeFromString(lastLaunch, fileModTime(info)), "launcher_profile", 70, "RobloxPlayerBeta.exe", defaultInfoSeverity, map[string]any{"launcherType": "official_roblox"}))
		candidateFiles = append(candidateFiles, executable)
	}

	for _, root := range roots.bloxstrap {
		executable := filepath.Join(root, "Bloxstrap.exe")
		info, err := os.Stat(executable)
		if err != nil {
			continue
		}
		status := "inactive"
		lastLaunch := ""
		tags := []string{"third_party"}
		if hasExistingPath(filepath.Join(root, "Modifications")) || hasExistingPath(filepath.Join(root, "ClientSettings")) {
			status = "customized"
			tags = append(tags, "custom_mods", "fastflags")
		}
		if process := findProcess(processTimeline, "Bloxstrap.exe"); process != nil {
			if status == "inactive" {
				status = "active"
			}
			lastLaunch = stringValue(process, "startTime")
		}
		profiles = append(profiles, launcherProfile("Bloxstrap", "bloxstrap", "", "third_party", executable, status, tags, info, lastLaunch))
		logs = append(logs, fileLog("executed_file", executable, "", "", timeFromString(lastLaunch, info.ModTime()), "launcher_profile", 70, "Bloxstrap.exe", defaultInfoSeverity, map[string]any{"launcherType": "bloxstrap"}))
		candidateFiles = append(candidateFiles, executable)
	}

	unknown, err := filepath.Glob(filepath.Join(roots.versionsRoot, "*", "*Roblox*.exe"))
	if err != nil {
		errs = append(errs, "unknown_glob")
	}
	for _, executable := range unknown {
		base := strings.ToLower(filepath.Base(executable))
		if base == "robloxplayerbeta.exe" || base == "robloxstudiobeta.exe" || base == "robloxcrashhandler.exe" {
			continue
		}
		if seen[normalizePath(executable)] {
			continue
		}
		seen[normalizePath(executable)] = true
		info, _ := os.Stat(executable)
		profiles = append(profiles, launcherProfile(filepath.Base(executable), "unknown_roblox_related", "", "", executable, "inactive", []string{"unknown"}, info, ""))
		candidateFiles = append(candidateFiles, executable)
	}

	if len(errs) > 0 {
		return profiles, logs, candidateFiles, joinErrors(errs)
	}
	return profiles, logs, candidateFiles, nil
}

func launcherProfile(name string, launcherType string, version string, channel string, executable string, status string, tags []string, info os.FileInfo, lastLaunch string) contract.LauncherProfile {
	updated := ""
	if info != nil {
		updated = info.ModTime().UTC().Format(time.RFC3339)
	}
	hash, hashStatus := hashFileIfAllowed(executable)
	metadata := map[string]any{
		"publisherStatus": "unavailable",
		"hashStatus":      hashStatus,
		"pathScope":       "approved_roblox_location",
	}
	return contract.LauncherProfile{
		ProfileName:    name,
		LauncherType:   launcherType,
		Version:        version,
		Channel:        channel,
		Path:           privacy.MaskPath(executable),
		ExecutableHash: hash,
		Status:         status,
		Tags:           tags,
		UpdateTime:     updated,
		LastLaunchTime: lastLaunch,
		Metadata:       privacy.RedactMap(metadata),
	}
}

func collectClientModAssets(ctx context.Context, roots roots) ([]contract.ClientModAsset, []contract.FileLog, []string, error) {
	_ = ctx
	assets := []contract.ClientModAsset{}
	logs := []contract.FileLog{}
	candidateFiles := []string{}
	errs := []string{}

	for _, root := range roots.bloxstrap {
		targets := []struct {
			name   string
			path   string
			source string
		}{
			{"Bloxstrap Modifications", filepath.Join(root, "Modifications"), "Bloxstrap"},
			{"Bloxstrap ClientSettings", filepath.Join(root, "ClientSettings"), "Bloxstrap"},
		}
		for _, target := range targets {
			summary, err := summarizeDirectory(target.path)
			if err != nil {
				continue
			}
			candidateFiles = append(candidateFiles, summary.StringCandidateFiles...)
			status := "customized"
			severity := defaultInfoSeverity
			if summary.RiskyFiles > 0 {
				status = "suspicious"
				severity = "WARNING"
			}
			assets = append(assets, assetFromSummary(target.name, target.source, target.path, status, summary))
			logs = append(logs, directoryFileLog(target.path, "data_change", "client_mod_asset", severity, summary))
		}
	}

	matches, err := filepath.Glob(filepath.Join(roots.versionsRoot, "*", "ClientSettings"))
	if err != nil {
		errs = append(errs, "roblox_client_settings_glob")
	}
	for _, dir := range matches {
		summary, err := summarizeDirectory(dir)
		if err != nil {
			continue
		}
		candidateFiles = append(candidateFiles, summary.StringCandidateFiles...)
		status := "customized"
		severity := defaultInfoSeverity
		if summary.RiskyFiles > 0 {
			status = "suspicious"
			severity = "WARNING"
		}
		assets = append(assets, assetFromSummary("Roblox ClientSettings", "RobloxPlayerBeta", dir, status, summary))
		logs = append(logs, directoryFileLog(dir, "data_change", "client_mod_asset", severity, summary))
	}

	if len(errs) > 0 {
		return assets, logs, candidateFiles, joinErrors(errs)
	}
	return assets, logs, candidateFiles, nil
}

type directorySummary struct {
	FileCount            int
	TotalSize            int64
	CreatedAt            time.Time
	ModifiedAt           time.Time
	RiskyFiles           int
	StringCandidateFiles []string
	Truncated            bool
}

func summarizeDirectory(root string) (directorySummary, error) {
	summary := directorySummary{}
	rootInfo, err := os.Stat(root)
	if err != nil {
		return summary, err
	}
	if !rootInfo.IsDir() {
		return summary, os.ErrInvalid
	}

	visited := 0
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		visited++
		if visited > MaxWalkFiles {
			summary.Truncated = true
			return filepath.SkipAll
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		summary.FileCount++
		summary.TotalSize += info.Size()
		if summary.CreatedAt.IsZero() || info.ModTime().Before(summary.CreatedAt) {
			summary.CreatedAt = info.ModTime().UTC()
		}
		if info.ModTime().After(summary.ModifiedAt) {
			summary.ModifiedAt = info.ModTime().UTC()
		}
		if isRiskyAssetExtension(path) {
			summary.RiskyFiles++
		}
		if isSafeStringCandidate(path, info.Size()) {
			summary.StringCandidateFiles = append(summary.StringCandidateFiles, path)
		}
		return nil
	})
	if err != nil {
		return summary, err
	}
	if summary.FileCount == 0 {
		summary.CreatedAt = rootInfo.ModTime().UTC()
		summary.ModifiedAt = rootInfo.ModTime().UTC()
	}
	return summary, nil
}

func assetFromSummary(name string, source string, path string, status string, summary directorySummary) contract.ClientModAsset {
	return contract.ClientModAsset{
		Name:           name,
		SourceLauncher: source,
		Path:           privacy.MaskPath(path),
		FileCount:      summary.FileCount,
		TotalSize:      summary.TotalSize,
		CreatedTime:    formatTime(summary.CreatedAt),
		ModifiedTime:   formatTime(summary.ModifiedAt),
		Status:         status,
		Metadata: privacy.RedactMap(map[string]any{
			"riskyFileCount": summary.RiskyFiles,
			"truncated":      summary.Truncated,
			"maxWalkFiles":   MaxWalkFiles,
		}),
	}
}

func collectProcessTimes(processTimeline []map[string]any, now time.Time) []contract.ProcessTime {
	rows := []contract.ProcessTime{}
	for _, process := range processTimeline {
		name := stringValue(process, "processName")
		if !isRobloxProcess(name) {
			continue
		}
		startedAt := stringValue(process, "startTime")
		duration := int64(0)
		if parsed, err := time.Parse(time.RFC3339, startedAt); err == nil && !parsed.IsZero() {
			duration = now.Sub(parsed).Milliseconds()
			if duration < 0 {
				duration = 0
			}
		}
		rows = append(rows, contract.ProcessTime{
			ProcessName: name,
			Path:        stringValue(process, "path"),
			FirstSeenAt: startedAt,
			LastSeenAt:  now.UTC().Format(time.RFC3339),
			StartedAt:   startedAt,
			DurationMs:  duration,
			Source:      "live_process",
			Status:      firstNonEmpty(stringValue(process, "status"), "observed"),
			Metadata: privacy.RedactMap(map[string]any{
				"pid":        process["pid"],
				"parentPid":  process["parentPid"],
				"parentName": process["parentName"],
			}),
		})
	}
	return rows
}

func collectExploreFileLogs(ctx context.Context, roots roots) ([]contract.FileLog, error) {
	_ = ctx
	logs := []contract.FileLog{}
	logs = append(logs, collectDownloadsLogs(roots.downloads)...)
	logs = append(logs, collectPrefetchLogs(roots.prefetch)...)
	return logs, nil
}

func collectDownloadsLogs(downloads string) []contract.FileLog {
	entries, err := os.ReadDir(downloads)
	if err != nil {
		return nil
	}
	logs := []contract.FileLog{}
	count := 0
	for _, entry := range entries {
		if count >= MaxDownloadRows {
			break
		}
		if entry.IsDir() || !isRobloxRelatedName(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		path := filepath.Join(downloads, entry.Name())
		severity := defaultInfoSeverity
		confidence := 55
		if isRiskyAssetExtension(path) {
			severity = "WARNING"
			confidence = 70
		}
		logs = append(logs, fileLog("downloaded_file", path, "", "", info.ModTime(), "downloads_metadata", confidence, "", severity, map[string]any{"directFolderOnly": true}))
		count++
	}
	return logs
}

func collectPrefetchLogs(prefetch string) []contract.FileLog {
	entries, err := os.ReadDir(prefetch)
	if err != nil {
		return nil
	}
	logs := []contract.FileLog{}
	count := 0
	for _, entry := range entries {
		if count >= MaxPrefetchRows {
			break
		}
		if entry.IsDir() || !isRobloxRelatedName(entry.Name()) || !strings.HasSuffix(strings.ToLower(entry.Name()), ".pf") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		path := filepath.Join(prefetch, entry.Name())
		logs = append(logs, fileLog("executed_file", path, "", "", info.ModTime(), "windows_prefetch_metadata", 60, relatedProcessFromPrefetch(entry.Name()), defaultInfoSeverity, map[string]any{"metadataOnly": true}))
		count++
	}
	return logs
}

func directoryFileLog(path string, action string, source string, severity string, summary directorySummary) contract.FileLog {
	return fileLog(action, path, "", "", summary.ModifiedAt, source, 65, "", severity, map[string]any{
		"fileCount":      summary.FileCount,
		"totalSize":      summary.TotalSize,
		"riskyFileCount": summary.RiskyFiles,
		"truncated":      summary.Truncated,
	})
}

func fileLog(action string, path string, oldPath string, newPath string, timestamp time.Time, source string, confidence int, relatedProcess string, severity string, metadata map[string]any) contract.FileLog {
	if (action == "renamed_file" || action == "moved_file") && (oldPath == "" || newPath == "") {
		action = "unknown"
	}
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	return contract.FileLog{
		Action:         action,
		Path:           privacy.MaskPath(path),
		OldPath:        privacy.MaskPath(oldPath),
		NewPath:        privacy.MaskPath(newPath),
		Timestamp:      timestamp.UTC().Format(time.RFC3339),
		Source:         source,
		Confidence:     confidence,
		RelatedProcess: relatedProcess,
		Severity:       firstNonEmpty(severity, defaultInfoSeverity),
		Metadata:       privacy.RedactMap(metadata),
	}
}

func findProcess(processTimeline []map[string]any, name string) map[string]any {
	for _, process := range processTimeline {
		if strings.EqualFold(stringValue(process, "processName"), name) {
			return process
		}
	}
	return nil
}

func isRobloxProcess(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "robloxplayerbeta.exe", "robloxstudiobeta.exe", "robloxcrashhandler.exe", "bloxstrap.exe":
		return true
	default:
		return false
	}
}

func isRobloxRelatedName(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "roblox") || strings.Contains(lower, "bloxstrap")
}

func isRiskyAssetExtension(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".exe", ".dll", ".ps1", ".bat", ".cmd", ".js", ".vbs", ".scr":
		return true
	default:
		return false
	}
}

func hashFileIfAllowed(path string) (string, string) {
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
	if info.Size() > MaxLauncherHashMB*1024*1024 {
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

func isSafeStringCandidate(path string, size int64) bool {
	if size <= 0 || size > 20*1024*1024 {
		return false
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json", ".txt", ".ini", ".cfg", ".toml", ".xml", ".lua", ".rbxm", ".rbxmx":
		return true
	default:
		return isRiskyAssetExtension(path)
	}
}

func relatedProcessFromPrefetch(name string) string {
	upper := strings.ToUpper(name)
	if strings.Contains(upper, "BLOXSTRAP") {
		return "Bloxstrap.exe"
	}
	if strings.Contains(upper, "ROBLOXSTUDIO") {
		return "RobloxStudioBeta.exe"
	}
	if strings.Contains(upper, "ROBLOXCRASHHANDLER") {
		return "RobloxCrashHandler.exe"
	}
	return "RobloxPlayerBeta.exe"
}

func stringValue(row map[string]any, key string) string {
	value, ok := row[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

func timeFromString(value string, fallback time.Time) time.Time {
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.UTC()
	}
	return fallback
}

func fileModTime(info os.FileInfo) time.Time {
	if info == nil {
		return time.Time{}
	}
	return info.ModTime().UTC()
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func hasExistingPath(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func normalizePath(path string) string {
	return strings.ToLower(filepath.Clean(path))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

type stringListError []string

func (err stringListError) Error() string {
	return strings.Join(err, ",")
}

func joinErrors(values []string) error {
	if len(values) == 0 {
		return nil
	}
	return stringListError(values)
}
