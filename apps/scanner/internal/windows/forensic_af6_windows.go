//go:build windows

package windows

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	gopsnet "github.com/shirou/gopsutil/v4/net"
	"golang.org/x/sys/windows/registry"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
	"github.com/moonetics/SideraScan/apps/scanner/internal/privacy"
)

const (
	af6CandidateLimit    = 160
	af6NetworkRowLimit   = 250
	af6DNSRowLimit       = 120
	af6HostsRowLimit     = 80
	af6USBRowLimit       = 80
	af6ADSMaxStreamCount = 12
)

type forensicAF6Result struct {
	FileTriage         []map[string]any
	NetworkConnections []map[string]any
	DNSCache           []map[string]any
	HostsEntries       []map[string]any
	Evidence           []contract.Evidence
	Findings           []contract.Finding
	Summary            map[string]any
	Warnings           []string
}

type triageCandidate struct {
	Path           string
	Name           string
	SourceArtifact string
	ReasonFlags    []string
	MaskedPathOnly bool
}

func collectFileNetworkForensics(ctx context.Context, snapshot BaselineSnapshot, options BaselineOptions, signatureCache map[string]signatureInfo) forensicAF6Result {
	result := forensicAF6Result{}
	reviewMode := forensicReviewMode(options.AdvancedForensics)
	rowLimit := options.AdvancedForensics.MaxRowsPerModule
	if rowLimit <= 0 {
		rowLimit = 500
	}
	maxHashMB := options.AdvancedForensics.MaxFileHashMB
	if maxHashMB <= 0 {
		maxHashMB = MaxExecutableHashMB
	}

	candidates := collectTriageCandidates(snapshot)
	scopedCandidates, scopedWarnings := collectAF6ScopedTriageCandidates()
	candidates = append(candidates, scopedCandidates...)
	result.Warnings = append(result.Warnings, scopedWarnings...)
	fileTriage := buildFileTriageRows(ctx, candidates, maxHashMB, signatureCache, rowLimit)

	networkRows, networkWarnings := collectAF6NetworkConnections(ctx, snapshot.ProcessTimeline)
	dnsRows, dnsWarnings := collectAF6DNSCache(ctx)
	hostsRows, hostsWarnings := collectAF6HostsEntries()
	usbRows, usbWarnings := collectAF6USBHistory()

	result.Warnings = append(result.Warnings, networkWarnings...)
	result.Warnings = append(result.Warnings, dnsWarnings...)
	result.Warnings = append(result.Warnings, hostsWarnings...)
	result.Warnings = append(result.Warnings, usbWarnings...)
	networkRows = append(networkRows, usbRows...)

	result.FileTriage = filterAF6Rows(fileTriage, reviewMode, rowLimit)
	result.NetworkConnections = filterAF6Rows(networkRows, reviewMode, rowLimit)
	result.DNSCache = filterAF6ContextRows(dnsRows, reviewMode, af6DNSRowLimit)
	result.HostsEntries = filterAF6Rows(hostsRows, reviewMode, af6HostsRowLimit)

	for _, row := range append(append([]map[string]any{}, result.FileTriage...), append(result.NetworkConnections, result.HostsEntries...)...) {
		if shouldCreateAF6Finding(row) {
			evidence, finding := buildAF6EvidenceFinding(row)
			result.Evidence = append(result.Evidence, evidence)
			result.Findings = append(result.Findings, finding)
		}
	}

	result.Summary = map[string]any{
		"reviewMode":         reviewMode,
		"fileTriage":         summarizeAF6Rows(fileTriage, result.FileTriage),
		"networkConnections": summarizeAF6Rows(networkRows, result.NetworkConnections),
		"dnsCache":           summarizeAF6Rows(dnsRows, result.DNSCache),
		"hostsEntries":       summarizeAF6Rows(hostsRows, result.HostsEntries),
		"bestEffortWarnings": uniqueStringsSorted(result.Warnings),
		"dnsScope":           "relevant_only",
		"packetCapture":      false,
		"browserHistoryRead": false,
		"fileContentUpload":  false,
		"adsContentRead":     false,
	}

	return result
}

func collectTriageCandidates(snapshot BaselineSnapshot) []triageCandidate {
	candidates := []triageCandidate{}
	add := func(path string, name string, source string, flags []string) {
		path = strings.TrimSpace(path)
		if path == "" || strings.HasPrefix(path, "HKLM\\") || strings.HasPrefix(path, "HKCU\\") {
			return
		}
		if !looksLikeFilesystemPath(path) {
			return
		}
		candidates = append(candidates, triageCandidate{
			Path:           path,
			Name:           firstNonEmptyString(name, filepath.Base(path)),
			SourceArtifact: source,
			ReasonFlags:    flags,
			MaskedPathOnly: strings.Contains(path, "***"),
		})
	}
	for _, row := range snapshot.ProcessTimeline {
		if statusNeedsReview(row) {
			add(stringFromAny(row["path"]), stringFromAny(row["processName"]), "process_timeline", stringsFromUnknown(row["suspiciousFlags"]))
		}
	}
	for _, row := range snapshot.LoadedModules {
		if statusNeedsReview(row) {
			add(stringFromAny(row["path"]), stringFromAny(row["moduleName"]), "loaded_modules", stringsFromUnknown(row["suspiciousFlags"]))
		}
	}
	for _, row := range append(append([]map[string]any{}, snapshot.Services...), append(snapshot.Drivers, snapshot.PersistenceItems...)...) {
		if statusNeedsReview(row) {
			add(stringFromAny(row["path"]), firstNonEmptyString(stringFromAny(row["name"]), stringFromAny(row["displayName"])), "services_drivers_persistence", stringsFromUnknown(row["suspiciousFlags"]))
		}
	}
	for _, row := range snapshot.ExecutionArtifacts {
		if statusNeedsReview(row) {
			add(stringFromAny(row["path"]), stringFromAny(row["name"]), "execution_artifacts", stringsFromUnknown(row["suspiciousFlags"]))
		}
	}
	return dedupeTriageCandidates(candidates)
}

func collectAF6ScopedTriageCandidates() ([]triageCandidate, []string) {
	roots := []struct {
		source string
		path   string
		depth  int
	}{
		{"downloads_scoped_triage", filepath.Join(os.Getenv("USERPROFILE"), "Downloads"), 1},
		{"temp_scoped_triage", os.TempDir(), 2},
		{"local_appdata_scoped_triage", os.Getenv("LOCALAPPDATA"), 1},
	}
	candidates := []triageCandidate{}
	warnings := []string{}
	for _, root := range roots {
		if strings.TrimSpace(root.path) == "" {
			continue
		}
		errStop := fmt.Errorf("af6 candidate cap")
		rootPath := filepath.Clean(root.path)
		err := filepath.WalkDir(rootPath, func(path string, entry os.DirEntry, err error) error {
			if err != nil || path == rootPath {
				return nil
			}
			depth := pathDepth(rootPath, path)
			if entry.IsDir() {
				if depth > root.depth || isBlockedContentFolder(entry.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if len(candidates) >= af6CandidateLimit {
				return errStop
			}
			if depth > root.depth || !isRiskyExecutionExtension(filepath.Ext(entry.Name())) {
				return nil
			}
			flags := af5FlagsForPath(entry.Name(), path)
			if len(flags) == 0 {
				return nil
			}
			candidates = append(candidates, triageCandidate{Path: path, Name: entry.Name(), SourceArtifact: root.source, ReasonFlags: flags})
			return nil
		})
		if err != nil && err != errStop {
			warnings = append(warnings, "af6_"+safeKey(root.source)+"_limited")
		}
	}
	return dedupeTriageCandidates(candidates), warnings
}

func buildFileTriageRows(ctx context.Context, candidates []triageCandidate, maxHashMB int, signatureCache map[string]signatureInfo, limit int) []map[string]any {
	rows := []map[string]any{}
	for _, candidate := range candidates {
		if len(rows) >= minPositive(limit, af6CandidateLimit) {
			break
		}
		var info os.FileInfo
		var err error
		if !candidate.MaskedPathOnly {
			info, err = os.Stat(candidate.Path)
		}
		missing := !candidate.MaskedPathOnly && err != nil
		flags := append([]string{}, candidate.ReasonFlags...)
		if missing {
			flags = append(flags, "path_deleted_or_missing")
		}
		status := "review"
		if containsString(flags, "windows_like_name_outside_windows") || containsString(flags, "unsigned_user_writable_path") || containsString(flags, "path_deleted_or_missing") {
			status = "suspicious"
		}
		signature := signatureInfo{Status: "not_checked"}
		if !candidate.MaskedPathOnly {
			signature = cachedSignature(ctx, candidate.Path, signatureCache)
		}
		if signature.Status == "unsigned" && isUserWritablePath(strings.ToLower(strings.ReplaceAll(candidate.Path, "/", `\`))) {
			flags = append(flags, "unsigned_user_writable_path")
			status = "suspicious"
		}
		if policyIsKnownVendorArtifact(candidate.Name, candidate.Path, signature.Publisher, signature.Signer) ||
			policyIsKnownBenignInstaller(candidate.Name, candidate.Path) ||
			policyIsKnownInstallerTempComponent(candidate.Name, candidate.Path) ||
			policyIsOfficialRobloxPath(candidate.Path) {
			status = "context"
			flags = append(flags, "benign_known_vendor_file")
		}
		if containsString(flags, "downloads_executable") && !containsString(flags, "windows_like_name_outside_windows") && !containsString(flags, "unsigned_user_writable_path") {
			status = "context"
			flags = append(flags, "historical_download_context")
		}
		severity := policyReviewSeverity(status)
		row := map[string]any{
			"fileName":          firstNonEmptyString(candidate.Name, filepath.Base(candidate.Path)),
			"extension":         strings.ToLower(filepath.Ext(candidate.Path)),
			"path":              privacy.MaskPath(candidate.Path),
			"sourceArtifact":    candidate.SourceArtifact,
			"reasonFlags":       uniqueStringsSorted(flags),
			"signatureStatus":   signature.Status,
			"signer":            signature.Signer,
			"publisher":         signature.Publisher,
			"status":            status,
			"severity":          severity,
			"confidence":        confidenceForTriage(status, flags),
			"hashPolicy":        "suspicious_candidates_only",
			"adsPolicy":         "suspicious_candidates_only",
			"maskedPathOnly":    candidate.MaskedPathOnly,
			"fileContentUpload": false,
			"source":            "af6_file_triage",
		}
		if candidate.MaskedPathOnly {
			row["hashStatus"] = "not_checked_masked_path"
			row["ads"] = map[string]any{"checked": false, "reason": "masked_path_only", "contentRead": false}
		} else if !missing {
			row["size"] = info.Size()
			row["modifiedTime"] = info.ModTime().UTC().Format(time.RFC3339)
			row["createdTime"] = fileCreatedTime(candidate.Path)
			row["accessedTime"] = ""
			if hash, hashStatus := hashExecutableIfAllowedMax(candidate.Path, maxHashMB); hashStatus != "" {
				row["hashStatus"] = hashStatus
				if hash != "" {
					row["sha256"] = hash
				}
			}
			row["ads"] = collectADSMetadata(candidate.Path)
		} else {
			row["missingFile"] = true
			row["hashStatus"] = "file_unavailable"
		}
		rows = append(rows, privacy.RedactMap(row))
	}
	return rows
}

func collectAF6NetworkConnections(ctx context.Context, processTimeline []map[string]any) ([]map[string]any, []string) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	connections, err := gopsnet.ConnectionsWithContext(timeoutCtx, "inet")
	if err != nil {
		return nil, []string{"af6_network_connections_unavailable"}
	}
	processIndex := processRowsByPID(processTimeline)
	rows := []map[string]any{}
	for _, connection := range connections {
		if len(rows) >= af6NetworkRowLimit {
			break
		}
		rowProcess := processIndex[connection.Pid]
		flags := networkReasonFlags(connection, rowProcess)
		status := "normal"
		severity := "INFO"
		confidence := 45
		if len(flags) > 0 {
			status = "review"
			severity = "INFO"
			confidence = 70
		}
		if len(flags) == 1 && containsString(flags, "remote_public_connection") {
			status = "context"
			severity = "INFO"
			confidence = 45
		}
		rows = append(rows, privacy.RedactMap(map[string]any{
			"pid":           connection.Pid,
			"processName":   stringFromAny(rowProcess["processName"]),
			"processPath":   rowProcess["path"],
			"protocol":      protocolName(connection.Type),
			"localAddress":  endpointString(connection.Laddr.IP, connection.Laddr.Port),
			"remoteAddress": endpointString(connection.Raddr.IP, connection.Raddr.Port),
			"state":         connection.Status,
			"reasonFlags":   flags,
			"status":        status,
			"severity":      severity,
			"confidence":    confidence,
			"source":        "gopsutil_net_connections",
			"packetCapture": false,
		}))
	}
	return rows, nil
}

func collectAF6DNSCache(ctx context.Context) ([]map[string]any, []string) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := hiddenCommand(timeoutCtx, "ipconfig.exe", "/displaydns").Output()
	if err != nil {
		return nil, []string{"af6_dns_cache_unavailable"}
	}
	rows := []map[string]any{}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		if len(rows) >= af6DNSRowLimit {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if !strings.Contains(strings.ToLower(line), "record name") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		domain := strings.TrimSpace(strings.TrimSuffix(parts[1], "."))
		if domain == "" || seen[strings.ToLower(domain)] || !isRelevantDNSDomain(domain) {
			continue
		}
		seen[strings.ToLower(domain)] = true
		rows = append(rows, privacy.RedactMap(map[string]any{
			"domain":       domain,
			"source":       "ipconfig_displaydns_relevant_only",
			"confidence":   35,
			"status":       "context",
			"severity":     "INFO",
			"reasonFlags":  dnsReasonFlags(domain),
			"dnsScope":     "relevant_only",
			"browserData":  false,
			"fullDNSCache": false,
		}))
	}
	if err := scanner.Err(); err != nil {
		return rows, []string{"af6_dns_cache_parse_limited"}
	}
	return rows, nil
}

func collectAF6HostsEntries() ([]map[string]any, []string) {
	hostsPath := filepath.Join(os.Getenv("SystemRoot"), `System32\drivers\etc\hosts`)
	if strings.TrimSpace(os.Getenv("SystemRoot")) == "" {
		hostsPath = `C:\Windows\System32\drivers\etc\hosts`
	}
	file, err := os.Open(hostsPath)
	if err != nil {
		return nil, []string{"af6_hosts_file_unavailable"}
	}
	defer file.Close()
	rows := []map[string]any{}
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if len(rows) >= af6HostsRowLimit {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		address := fields[0]
		for _, host := range fields[1:] {
			if !isSuspiciousHostEntry(address, host) {
				continue
			}
			rows = append(rows, privacy.RedactMap(map[string]any{
				"host":        host,
				"address":     redactIPAddress(address),
				"lineNumber":  lineNumber,
				"source":      "windows_hosts_file",
				"confidence":  78,
				"status":      "review",
				"severity":    "WARNING",
				"reasonFlags": hostsReasonFlags(address, host),
			}))
		}
	}
	if err := scanner.Err(); err != nil {
		return rows, []string{"af6_hosts_file_parse_limited"}
	}
	return rows, nil
}

func collectAF6USBHistory() ([]map[string]any, []string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Enum\USBSTOR`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, []string{"af6_usbstor_unavailable"}
	}
	defer key.Close()
	deviceClasses, err := key.ReadSubKeyNames(0)
	if err != nil {
		return nil, []string{"af6_usbstor_names_unavailable"}
	}
	rows := []map[string]any{}
	for _, className := range deviceClasses {
		if len(rows) >= af6USBRowLimit {
			break
		}
		classKey, err := registry.OpenKey(key, className, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		instances, _ := classKey.ReadSubKeyNames(0)
		_ = classKey.Close()
		for _, instance := range instances {
			if len(rows) >= af6USBRowLimit {
				break
			}
			instanceKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Enum\USBSTOR\`+className+`\`+instance, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			info, _ := instanceKey.Stat()
			friendlyName, _, _ := instanceKey.GetStringValue("FriendlyName")
			manufacturer, _, _ := instanceKey.GetStringValue("Mfg")
			_ = instanceKey.Close()
			rows = append(rows, privacy.RedactMap(map[string]any{
				"forensicSource": "usb_history",
				"deviceClass":    privacy.RedactString(className),
				"deviceLabel":    privacy.RedactString(firstNonEmptyString(friendlyName, className)),
				"manufacturer":   privacy.RedactString(manufacturer),
				"lastSeenAt":     registryModTime(info),
				"source":         "windows_registry_usbstor",
				"confidence":     35,
				"status":         "context",
				"severity":       "INFO",
				"reasonFlags":    []string{"usb_history_context"},
				"serialRedacted": true,
			}))
		}
	}
	return rows, nil
}

func collectADSMetadata(path string) map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := hiddenCommand(ctx, "cmd.exe", "/c", "dir", "/r", path).Output()
	if err != nil {
		return map[string]any{"checked": true, "available": false}
	}
	streams := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.Contains(line, ":$DATA") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) > 0 {
			streamName := parts[len(parts)-1]
			streamName = strings.TrimSuffix(streamName, ":$DATA")
			if streamName != "" && !strings.Contains(streamName, filepath.Base(path)) {
				streams = append(streams, privacy.RedactString(streamName))
			}
		}
		if len(streams) >= af6ADSMaxStreamCount {
			break
		}
	}
	return map[string]any{"checked": true, "streamCount": len(streams), "streamNames": uniqueStringsSorted(streams), "contentRead": false}
}

func statusNeedsReview(row map[string]any) bool {
	status := strings.ToLower(stringFromAny(row["status"]))
	severity := strings.ToUpper(stringFromAny(row["severity"]))
	return status == "review" || status == "suspicious" || status == "missing_file" || severity == "WARNING" || severity == "SEVERE" || severity == "CRITICAL"
}

func dedupeTriageCandidates(candidates []triageCandidate) []triageCandidate {
	seen := map[string]triageCandidate{}
	for _, candidate := range candidates {
		key := strings.ToLower(candidate.Path)
		if key == "" {
			continue
		}
		existing := seen[key]
		existing.Path = candidate.Path
		existing.Name = firstNonEmptyString(existing.Name, candidate.Name)
		existing.SourceArtifact = firstNonEmptyString(existing.SourceArtifact, candidate.SourceArtifact)
		existing.ReasonFlags = uniqueStringsSorted(append(existing.ReasonFlags, candidate.ReasonFlags...))
		seen[key] = existing
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]triageCandidate, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}

func processRowsByPID(rows []map[string]any) map[int32]map[string]any {
	out := map[int32]map[string]any{}
	for _, row := range rows {
		pid := int32(intFromAnyDefault(row["pid"], 0))
		if pid > 0 {
			out[pid] = row
		}
	}
	return out
}

func networkReasonFlags(connection gopsnet.ConnectionStat, process map[string]any) []string {
	flags := []string{}
	if connection.Raddr.IP != "" && !isPrivateOrLoopbackIP(connection.Raddr.IP) {
		flags = append(flags, "remote_public_connection")
	}
	if statusNeedsReview(process) && connection.Raddr.IP != "" {
		flags = append(flags, "suspicious_process_network_activity")
	}
	if connection.Raddr.Port == 4444 || connection.Raddr.Port == 1337 || connection.Raddr.Port == 8080 {
		flags = append(flags, "interesting_remote_port")
	}
	return uniqueStringsSorted(flags)
}

func protocolName(connectionType uint32) string {
	switch connectionType {
	case 1:
		return "tcp"
	case 2:
		return "udp"
	default:
		return fmt.Sprintf("type_%d", connectionType)
	}
}

func endpointString(ip string, port uint32) string {
	if ip == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

func isPrivateOrLoopbackIP(value string) bool {
	ip := net.ParseIP(value)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func isRelevantDNSDomain(domain string) bool {
	return len(dnsReasonFlags(domain)) > 0
}

func dnsReasonFlags(domain string) []string {
	lower := strings.ToLower(domain)
	flags := []string{}
	for _, marker := range []string{"roblox", "bloxstrap", "discord", "telegram", "pastebin", "githubusercontent", "raw.githubusercontent", "cdn.discordapp", "inject", "loader", "cheat", "exploit", "synapse", "script"} {
		if strings.Contains(lower, marker) {
			flags = append(flags, "dns_"+safeKey(marker))
		}
	}
	return uniqueStringsSorted(flags)
}

func isSuspiciousHostEntry(address string, host string) bool {
	return len(hostsReasonFlags(address, host)) > 0
}

func hostsReasonFlags(address string, host string) []string {
	lowerHost := strings.ToLower(host)
	flags := []string{}
	if address == "0.0.0.0" || address == "127.0.0.1" || address == "::1" {
		for _, marker := range []string{"microsoft", "windowsupdate", "defender", "roblox", "bloxstrap", "siderascan"} {
			if strings.Contains(lowerHost, marker) {
				flags = append(flags, "hosts_blocks_"+safeKey(marker))
			}
		}
	}
	return uniqueStringsSorted(flags)
}

func redactIPAddress(value string) string {
	if net.ParseIP(value) == nil {
		return privacy.RedactString(value)
	}
	return "[REDACTED_IP]"
}

func registryModTime(info *registry.KeyInfo) string {
	if info == nil || info.ModTime().IsZero() {
		return ""
	}
	return info.ModTime().UTC().Format(time.RFC3339)
}

func filterAF6Rows(rows []map[string]any, reviewMode string, limit int) []map[string]any {
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

func filterAF6ContextRows(rows []map[string]any, reviewMode string, limit int) []map[string]any {
	filtered := []map[string]any{}
	for _, row := range rows {
		if reviewMode == "ai_assisted_full" || len(stringsFromUnknown(row["reasonFlags"])) > 0 {
			filtered = append(filtered, row)
		}
		if limit > 0 && len(filtered) >= limit {
			break
		}
	}
	return filtered
}

func summarizeAF6Rows(allRows []map[string]any, uploadedRows []map[string]any) map[string]any {
	return map[string]any{
		"total":          len(allRows),
		"uploaded":       len(uploadedRows),
		"statusCounts":   countStringField(allRows, "status"),
		"severityCounts": countStringField(allRows, "severity"),
	}
}

func shouldCreateAF6Finding(row map[string]any) bool {
	source := strings.ToLower(firstNonEmptyString(stringFromAny(row["source"]), stringFromAny(row["forensicSource"])))
	status := strings.ToLower(stringFromAny(row["status"]))
	severity := strings.ToUpper(stringFromAny(row["severity"]))
	flags := append(stringsFromUnknown(row["reasonFlags"]), stringsFromUnknown(row["suspiciousFlags"])...)
	if strings.Contains(source, "dns") || strings.Contains(source, "usb") {
		return false
	}
	if strings.Contains(source, "hosts") {
		return len(flags) > 0
	}
	if strings.Contains(strings.ToLower(fmt.Sprint(row["reasonFlags"])), "benign_") ||
		strings.Contains(strings.ToLower(fmt.Sprint(row["reasonFlags"])), "historical_download_context") {
		return false
	}
	if isWeakMissingOnlyTriage(row, flags) {
		return false
	}
	return policyShouldCreateFinding(status, severity, flags, stringFromAny(row["signatureStatus"]))
}

func buildAF6EvidenceFinding(row map[string]any) (contract.Evidence, contract.Finding) {
	title := firstNonEmptyString(stringFromAny(row["fileName"]), stringFromAny(row["processName"]), stringFromAny(row["host"]), stringFromAny(row["path"]), "Forensic triage item")
	source := firstNonEmptyString(stringFromAny(row["source"]), stringFromAny(row["sourceArtifact"]), "af6")
	evidenceID := fmt.Sprintf("af6-%s-%x", safeKey(source), fnv32(title+stringFromAny(row["path"])+stringFromAny(row["remoteAddress"])))
	severity := firstNonEmptyString(stringFromAny(row["severity"]), "WARNING")
	evidence := contract.Evidence{
		ClientEvidenceID: evidenceID,
		Type:             "af6_context",
		Title:            "File/network triage item: " + title,
		Data:             privacy.RedactMap(row),
	}
	finding := contract.Finding{
		Category:     "FILE",
		Severity:     severity,
		Title:        "Forensic triage item requires review: " + title,
		Message:      "A scoped file, network, or hosts artifact matched forensic review heuristics.",
		EvidenceRef:  evidenceID,
		Confidence:   intFromAnyDefault(row["confidence"], 70),
		SourceModule: "file_network_triage",
		Metadata: privacy.RedactMap(map[string]any{
			"source":      source,
			"path":        row["path"],
			"reasonFlags": row["reasonFlags"],
			"remote":      row["remoteAddress"],
			"host":        row["host"],
		}),
	}
	return evidence, finding
}

func looksLikeFilesystemPath(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" || strings.Contains(lower, "***") {
		return true
	}
	if strings.Contains(lower, `:\`) || strings.Contains(lower, ":/") || strings.HasPrefix(lower, `\\`) {
		return true
	}
	if strings.Contains(lower, `\`) || strings.Contains(lower, `/`) {
		return true
	}
	return false
}

func isWeakMissingOnlyTriage(row map[string]any, flags []string) bool {
	if len(flags) == 0 {
		return false
	}
	for _, flag := range flags {
		if flag != "missing_file" && flag != "path_deleted_or_missing" && flag != "localappdata_path" {
			return false
		}
	}
	pathValue := strings.ToLower(strings.ReplaceAll(stringFromAny(row["path"]), "/", `\`))
	name := strings.ToLower(stringFromAny(row["fileName"]))
	if pathValue == `c:\program` || pathValue == `c:\program files` || pathValue == `c:\program files (x86)` {
		return true
	}
	if strings.Contains(pathValue, `\windows\system32\drivers\`) || strings.Contains(pathValue, `\program files\`) || strings.Contains(pathValue, `\program files (x86)\`) {
		return true
	}
	if strings.Contains(pathValue, `\dockerdesktop\`) || strings.Contains(name, "docker") || strings.Contains(name, "openvpn") {
		return true
	}
	return false
}

func confidenceForTriage(status string, flags []string) int {
	if strings.EqualFold(status, "suspicious") {
		return 84
	}
	if len(flags) >= 2 {
		return 76
	}
	return 66
}

func minPositive(values ...int) int {
	out := 0
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if out == 0 || value < out {
			out = value
		}
	}
	if out == 0 {
		return af6CandidateLimit
	}
	return out
}
