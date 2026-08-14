//go:build windows

package windows

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
	"github.com/moonetics/SideraScan/apps/scanner/internal/privacy"
)

const (
	af7TimelineLimit              = 900
	af7ArtifactChainWindow        = 30 * time.Minute
	af7InvestigationContextWindow = 2 * time.Hour
)

type forensicAF7Result struct {
	Timeline []map[string]any
	Evidence []contract.Evidence
	Findings []contract.Finding
	Summary  map[string]any
	Warnings []string
}

type timelineEntry struct {
	ID                  string
	When                time.Time
	HasTime             bool
	SourceModule        string
	EventType           string
	Title               string
	Subject             string
	Path                string
	ProcessName         string
	PID                 int
	Severity            string
	Status              string
	Confidence          int
	EvidenceRefs        []string
	CorrelationID       string
	ReasonFlags         []string
	TimestampConfidence string
	Metadata            map[string]any
}

type correlationGroup struct {
	ID             string
	Title          string
	Message        string
	Severity       string
	Confidence     int
	ReasonFlags    []string
	SourceModules  []string
	TimelineIDs    []string
	EvidenceRefs   []string
	Representative map[string]any
}

func collectForensicTimelineCorrelation(snapshot BaselineSnapshot, options BaselineOptions) forensicAF7Result {
	result := forensicAF7Result{}
	reviewMode := forensicReviewMode(options.AdvancedForensics)
	entries := buildForensicTimelineEntries(snapshot)
	groups := correlateForensicTimeline(entries)

	for _, group := range groups {
		evidence, finding := buildAF7EvidenceFinding(group)
		result.Evidence = append(result.Evidence, evidence)
		result.Findings = append(result.Findings, finding)
		for index := range entries {
			if containsString(group.TimelineIDs, entries[index].ID) {
				entries[index].CorrelationID = group.ID
				entries[index].EvidenceRefs = uniqueStringsSorted(append(entries[index].EvidenceRefs, evidence.ClientEvidenceID))
			}
		}
	}

	result.Timeline = timelineEntriesToRows(entries, af7TimelineLimit)
	result.Summary = map[string]any{
		"reviewMode":           reviewMode,
		"timelineRows":         len(result.Timeline),
		"correlationFindings":  len(result.Findings),
		"sourceCounts":         countTimelineStringField(result.Timeline, "sourceModule"),
		"severityCounts":       countTimelineStringField(result.Timeline, "severity"),
		"topCorrelations":      topCorrelationTitles(groups, 6),
		"bestEffortWarnings":   uniqueStringsSorted(result.Warnings),
		"correlationWindow":    "30m artifact chain, 2h investigation context",
		"multiSignalRequired":  true,
		"singleNameEscalation": false,
	}
	return result
}

func buildForensicTimelineEntries(snapshot BaselineSnapshot) []timelineEntry {
	entries := []timelineEntry{}
	addRows := func(source string, eventType string, rows []map[string]any) {
		for _, row := range rows {
			entries = append(entries, timelineEntryFromRow(source, eventType, row))
		}
	}

	addRows("process_timeline", "process_observed", snapshot.ProcessTimeline)
	for _, log := range snapshot.FileLogs {
		entries = append(entries, timelineEntryFromFileLog(log))
	}
	addRows("loaded_modules", "dll_loaded", snapshot.LoadedModules)
	addRows("process_handles", "process_handle", snapshot.ProcessHandles)
	addRows("services", "service", snapshot.Services)
	addRows("drivers", "driver", snapshot.Drivers)
	addRows("persistence", "persistence", snapshot.PersistenceItems)
	addRows("event_logs", "windows_event", snapshot.EventLogs)
	addRows("defender_events", "defender_event", snapshot.DefenderEvents)
	addRows("execution_artifacts", "execution_artifact", snapshot.ExecutionArtifacts)
	addRows("network_connections", "network_connection", snapshot.NetworkConnections)
	addRows("file_triage", "file_triage", snapshot.FileTriage)

	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].HasTime != entries[j].HasTime {
			return entries[i].HasTime
		}
		if entries[i].HasTime && !entries[i].When.Equal(entries[j].When) {
			return entries[i].When.Before(entries[j].When)
		}
		if entries[i].SourceModule != entries[j].SourceModule {
			return entries[i].SourceModule < entries[j].SourceModule
		}
		return entries[i].Title < entries[j].Title
	})

	for index := range entries {
		if entries[index].ID == "" {
			entries[index].ID = fmt.Sprintf("tl_%03d_%x", index+1, fnv32(entries[index].SourceModule+entries[index].Title+entries[index].Path))
		}
	}
	return entries
}

func timelineEntryFromFileLog(log contract.FileLog) timelineEntry {
	row := map[string]any{
		"action":         log.Action,
		"path":           log.Path,
		"oldPath":        log.OldPath,
		"newPath":        log.NewPath,
		"timestamp":      log.Timestamp,
		"source":         log.Source,
		"confidence":     log.Confidence,
		"relatedProcess": log.RelatedProcess,
		"severity":       log.Severity,
		"metadata":       log.Metadata,
	}
	return timelineEntryFromRow("file_logs", firstNonEmptyString(log.Action, "file_log"), row)
}

func timelineEntryFromRow(sourceModule string, defaultEventType string, row map[string]any) timelineEntry {
	when, hasTime := firstTimestampFromRow(row)
	title := firstNonEmptyString(
		stringFromAny(row["title"]),
		stringFromAny(row["name"]),
		stringFromAny(row["fileName"]),
		stringFromAny(row["moduleName"]),
		stringFromAny(row["processName"]),
		stringFromAny(row["serviceName"]),
		stringFromAny(row["driverName"]),
		stringFromAny(row["event"]),
		defaultEventType,
	)
	subject := firstNonEmptyString(
		stringFromAny(row["subject"]),
		stringFromAny(row["targetProcessName"]),
		stringFromAny(row["sourceProcessName"]),
		stringFromAny(row["host"]),
		stringFromAny(row["domain"]),
		title,
	)
	path := firstNonEmptyString(
		stringFromAny(row["path"]),
		stringFromAny(row["sourcePath"]),
		stringFromAny(row["imagePath"]),
		stringFromAny(row["oldPath"]),
		stringFromAny(row["newPath"]),
	)
	eventType := firstNonEmptyString(
		stringFromAny(row["eventType"]),
		stringFromAny(row["artifactType"]),
		stringFromAny(row["action"]),
		stringFromAny(row["type"]),
		defaultEventType,
	)
	source := firstNonEmptyString(stringFromAny(row["sourceModule"]), stringFromAny(row["source"]), sourceModule)
	severity := strings.ToUpper(firstNonEmptyString(stringFromAny(row["severity"]), "INFO"))
	status := strings.ToLower(firstNonEmptyString(stringFromAny(row["status"]), "context"))
	confidence := intFromAnyDefault(row["confidence"], 50)
	flags := uniqueStringsSorted(append(stringsFromUnknown(row["reasonFlags"]), stringsFromUnknown(row["suspiciousFlags"])...))
	metadata := privacy.RedactMap(map[string]any{
		"rawSource":        source,
		"signatureStatus":  row["signatureStatus"],
		"publisher":        row["publisher"],
		"signer":           row["signer"],
		"accessRights":     row["accessRights"],
		"remoteAddress":    row["remoteAddress"],
		"localAddress":     row["localAddress"],
		"confidenceSource": row["confidence"],
	})

	return timelineEntry{
		When:                when,
		HasTime:             hasTime,
		SourceModule:        sourceModule,
		EventType:           eventType,
		Title:               title,
		Subject:             subject,
		Path:                privacy.MaskPath(path),
		ProcessName:         firstNonEmptyString(stringFromAny(row["processName"]), stringFromAny(row["targetProcessName"]), stringFromAny(row["sourceProcessName"]), stringFromAny(row["relatedProcess"])),
		PID:                 intFromAnyDefault(firstNonNil(row["pid"], row["targetPid"], row["sourcePid"]), 0),
		Severity:            severity,
		Status:              status,
		Confidence:          confidence,
		EvidenceRefs:        evidenceRefsFromRow(row),
		ReasonFlags:         flags,
		TimestampConfidence: timestampConfidence(hasTime),
		Metadata:            metadata,
	}
}

func timelineEntriesToRows(entries []timelineEntry, limit int) []map[string]any {
	rows := make([]map[string]any, 0, minInt(len(entries), limit))
	for index, entry := range entries {
		if len(rows) >= limit {
			break
		}
		timestamp := ""
		if entry.HasTime {
			timestamp = entry.When.UTC().Format(time.RFC3339)
		}
		row := map[string]any{
			"id":                  firstNonEmptyString(entry.ID, fmt.Sprintf("tl_%03d", index+1)),
			"timestamp":           timestamp,
			"timestampConfidence": entry.TimestampConfidence,
			"sourceModule":        entry.SourceModule,
			"eventType":           entry.EventType,
			"title":               entry.Title,
			"subject":             entry.Subject,
			"path":                entry.Path,
			"processName":         entry.ProcessName,
			"pid":                 entry.PID,
			"severity":            entry.Severity,
			"status":              entry.Status,
			"confidence":          entry.Confidence,
			"evidenceRefs":        uniqueStringsSorted(entry.EvidenceRefs),
			"correlationId":       entry.CorrelationID,
			"reasonFlags":         uniqueStringsSorted(entry.ReasonFlags),
			"metadata":            entry.Metadata,
		}
		rows = append(rows, privacy.RedactMap(row))
	}
	return rows
}

func correlateForensicTimeline(entries []timelineEntry) []correlationGroup {
	groups := []correlationGroup{}
	groups = append(groups, correlateSuspiciousRobloxProcess(entries)...)
	groups = append(groups, correlateSuspiciousRobloxModules(entries)...)
	groups = append(groups, correlatePersistenceWithSuspiciousArtifacts(entries)...)
	groups = append(groups, correlateDefenderExclusions(entries)...)
	groups = append(groups, correlateEventLogCleared(entries)...)
	groups = append(groups, correlateArtifactChains(entries)...)
	return dedupeCorrelationGroups(groups)
}

func correlateSuspiciousRobloxProcess(entries []timelineEntry) []correlationGroup {
	roblox := filterEntries(entries, func(entry timelineEntry) bool {
		return entry.SourceModule == "process_timeline" && isRobloxName(entry.ProcessName)
	})
	suspicious := filterEntries(entries, func(entry timelineEntry) bool {
		return entry.SourceModule == "process_timeline" && statusEntryNeedsReview(entry) && !isRobloxName(entry.ProcessName) && hasMultiSignal(entry)
	})
	groups := []correlationGroup{}
	for _, suspect := range suspicious {
		if nearAny(suspect, roblox, af7ArtifactChainWindow) {
			groups = append(groups, newCorrelationGroup(
				"suspicious_process_near_roblox",
				"Suspicious process observed near Roblox",
				"Process metadata and timing indicate a review-worthy process near Roblox activity.",
				"WARNING",
				82,
				[]timelineEntry{suspect, nearestEntry(suspect, roblox)},
				suspect.ReasonFlags,
			))
		}
	}
	return groups
}

func correlateSuspiciousRobloxModules(entries []timelineEntry) []correlationGroup {
	groups := []correlationGroup{}
	for _, entry := range entries {
		if entry.SourceModule != "loaded_modules" || !statusEntryNeedsReview(entry) || !isRobloxName(entry.Subject+entry.ProcessName) || !hasMultiSignal(entry) {
			continue
		}
		severity := "WARNING"
		if containsString(entry.ReasonFlags, "unsigned_user_writable_path") || containsString(entry.ReasonFlags, "temp_path") {
			severity = "SEVERE"
		}
		groups = append(groups, newCorrelationGroup(
			"suspicious_dll_loaded_into_roblox",
			"Suspicious DLL loaded into Roblox process",
			"DLL metadata, process target, and path/signature flags require review.",
			severity,
			88,
			[]timelineEntry{entry},
			entry.ReasonFlags,
		))
	}
	return groups
}

func correlatePersistenceWithSuspiciousArtifacts(entries []timelineEntry) []correlationGroup {
	context := filterEntries(entries, func(entry timelineEntry) bool {
		return (entry.SourceModule == "file_triage" || entry.SourceModule == "process_timeline" || entry.SourceModule == "execution_artifacts") && statusEntryNeedsReview(entry)
	})
	persistence := filterEntries(entries, func(entry timelineEntry) bool {
		return (entry.SourceModule == "services" || entry.SourceModule == "drivers" || entry.SourceModule == "persistence") && statusEntryNeedsReview(entry) && hasMultiSignal(entry)
	})
	groups := []correlationGroup{}
	for _, item := range persistence {
		near := nearestEntry(item, context)
		if near.ID != "" && (sameSubjectFamily(item, near) || nearTime(item, near, af7InvestigationContextWindow)) {
			groups = append(groups, newCorrelationGroup(
				"persistence_near_suspicious_artifact",
				"Persistence item correlates with suspicious artifact",
				"Service, driver, or autorun metadata lines up with a suspicious process/file artifact.",
				"WARNING",
				84,
				[]timelineEntry{item, near},
				append(item.ReasonFlags, near.ReasonFlags...),
			))
		}
	}
	return groups
}

func correlateDefenderExclusions(entries []timelineEntry) []correlationGroup {
	suspicious := filterEntries(entries, func(entry timelineEntry) bool {
		return (entry.SourceModule == "file_triage" || entry.SourceModule == "process_timeline" || entry.SourceModule == "execution_artifacts") && statusEntryNeedsReview(entry)
	})
	groups := []correlationGroup{}
	for _, defender := range entries {
		if defender.SourceModule != "defender_events" || !statusEntryNeedsReview(defender) {
			continue
		}
		if !containsAnyFlag(defender.ReasonFlags, []string{"defender_exclusion", "defender_disabled", "protection_reduced", "temp_path", "appdata_path", "downloads_path"}) {
			continue
		}
		near := nearestEntry(defender, suspicious)
		if near.ID != "" && (sameSubjectFamily(defender, near) || nearTime(defender, near, af7InvestigationContextWindow)) {
			groups = append(groups, newCorrelationGroup(
				"defender_change_near_suspicious_artifact",
				"Defender change correlates with suspicious artifact",
				"Defender exclusion or protection event appears near a suspicious process/file signal.",
				"WARNING",
				82,
				[]timelineEntry{defender, near},
				append(defender.ReasonFlags, near.ReasonFlags...),
			))
		}
	}
	return groups
}

func correlateEventLogCleared(entries []timelineEntry) []correlationGroup {
	review := filterEntries(entries, func(entry timelineEntry) bool {
		return statusEntryNeedsReview(entry) && entry.SourceModule != "event_logs"
	})
	groups := []correlationGroup{}
	for _, event := range entries {
		if event.SourceModule != "event_logs" || !strings.Contains(strings.ToLower(event.Title+" "+event.EventType), "cleared") {
			continue
		}
		near := nearestEntry(event, review)
		if near.ID != "" && nearTime(event, near, af7InvestigationContextWindow) {
			groups = append(groups, newCorrelationGroup(
				"event_log_cleared_near_suspicious_activity",
				"Event log cleared near suspicious activity",
				"Log clearing is correlated with another review-worthy forensic signal.",
				"SEVERE",
				90,
				[]timelineEntry{event, near},
				append(event.ReasonFlags, near.ReasonFlags...),
			))
		}
	}
	return groups
}

func correlateArtifactChains(entries []timelineEntry) []correlationGroup {
	bySubject := map[string][]timelineEntry{}
	for _, entry := range entries {
		if entry.SourceModule != "file_logs" && entry.SourceModule != "execution_artifacts" {
			continue
		}
		key := artifactSubjectKey(entry)
		if key == "" {
			continue
		}
		bySubject[key] = append(bySubject[key], entry)
	}
	groups := []correlationGroup{}
	for _, chain := range bySubject {
		if len(chain) < 2 {
			continue
		}
		sort.SliceStable(chain, func(i, j int) bool {
			if chain[i].HasTime != chain[j].HasTime {
				return chain[i].HasTime
			}
			return chain[i].When.Before(chain[j].When)
		})
		actions := map[string]bool{}
		selected := []timelineEntry{}
		for _, entry := range chain {
			lower := strings.ToLower(entry.EventType + " " + entry.Title)
			for _, action := range []string{"downloaded", "executed", "deleted", "created"} {
				if strings.Contains(lower, action) {
					actions[action] = true
				}
			}
			if statusEntryNeedsReview(entry) || len(entry.ReasonFlags) > 0 || strings.ToUpper(entry.Severity) == "WARNING" {
				selected = append(selected, entry)
			}
		}
		if len(selected) == 0 || len(actions) < 2 {
			continue
		}
		if len(selected) > 3 {
			selected = selected[:3]
		}
		severity := "WARNING"
		if actions["downloaded"] && actions["executed"] && actions["deleted"] {
			severity = "SEVERE"
		}
		groups = append(groups, newCorrelationGroup(
			"download_execute_delete_artifact_chain",
			"Downloaded/executed/deleted artifact chain",
			"Multiple file-use artifacts describe a review-worthy execution chain.",
			severity,
			86,
			selected,
			collectEntryFlags(selected),
		))
	}
	return groups
}

func newCorrelationGroup(kind string, title string, message string, severity string, confidence int, entries []timelineEntry, flags []string) correlationGroup {
	timelineIDs := make([]string, 0, len(entries))
	evidenceRefs := []string{}
	sources := []string{}
	for _, entry := range entries {
		if entry.ID == "" {
			continue
		}
		timelineIDs = append(timelineIDs, entry.ID)
		evidenceRefs = append(evidenceRefs, entry.EvidenceRefs...)
		sources = append(sources, entry.SourceModule)
	}
	id := fmt.Sprintf("corr_%s_%x", safeKey(kind), fnv32(strings.Join(timelineIDs, "|")+title))
	return correlationGroup{
		ID:            id,
		Title:         title,
		Message:       message,
		Severity:      severity,
		Confidence:    confidence,
		ReasonFlags:   uniqueStringsSorted(append(flags, kind)),
		SourceModules: uniqueStringsSorted(sources),
		TimelineIDs:   uniqueStringsSorted(timelineIDs),
		EvidenceRefs:  uniqueStringsSorted(evidenceRefs),
		Representative: privacy.RedactMap(map[string]any{
			"kind":          kind,
			"sourceModules": uniqueStringsSorted(sources),
			"timelineIds":   uniqueStringsSorted(timelineIDs),
		}),
	}
}

func buildAF7EvidenceFinding(group correlationGroup) (contract.Evidence, contract.Finding) {
	evidence := contract.Evidence{
		ClientEvidenceID: group.ID,
		Type:             "forensic_correlation",
		Title:            group.Title,
		Data: privacy.RedactMap(map[string]any{
			"timelineIds":   group.TimelineIDs,
			"sourceModules": group.SourceModules,
			"reasonFlags":   group.ReasonFlags,
			"confidence":    group.Confidence,
			"summary":       group.Message,
		}),
	}
	finding := contract.Finding{
		Category:     "INTEGRITY",
		Severity:     group.Severity,
		Title:        group.Title,
		Message:      group.Message,
		EvidenceRef:  evidence.ClientEvidenceID,
		Confidence:   group.Confidence,
		SourceModule: "forensic_correlation",
		Metadata: privacy.RedactMap(map[string]any{
			"correlationId": group.ID,
			"timelineIds":   group.TimelineIDs,
			"sourceModules": group.SourceModules,
			"reasonFlags":   group.ReasonFlags,
		}),
	}
	return evidence, finding
}

func firstTimestampFromRow(row map[string]any) (time.Time, bool) {
	for _, key := range []string{"timestamp", "createdAt", "startedAt", "startTime", "firstSeenAt", "modifiedTime", "updateTime", "lastSeenAt", "finishedAt", "date"} {
		if parsed, ok := parseTimelineTime(stringFromAny(row[key])); ok {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func parseTimelineTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "unknown") {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05 -0700 MST", "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func evidenceRefsFromRow(row map[string]any) []string {
	refs := []string{}
	refs = append(refs, stringFromAny(row["evidenceRef"]))
	refs = append(refs, stringFromAny(row["clientEvidenceId"]))
	refs = append(refs, stringsFromUnknown(row["evidenceRefs"])...)
	return uniqueStringsSorted(refs)
}

func firstNonNil(values ...any) any {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func timestampConfidence(hasTime bool) string {
	if hasTime {
		return "observed"
	}
	return "unknown"
}

func statusEntryNeedsReview(entry timelineEntry) bool {
	status := strings.ToLower(entry.Status)
	severity := strings.ToUpper(entry.Severity)
	if status == "suspicious" || status == "flagged" || severity == "SEVERE" || severity == "CRITICAL" {
		return true
	}
	if status == "missing_file" || severity == "WARNING" {
		return policyStrongSignalCount(entry.ReasonFlags, stringFromAny(entry.Metadata["signatureStatus"])) >= 1
	}
	if status == "review" {
		return policyStrongSignalCount(entry.ReasonFlags, stringFromAny(entry.Metadata["signatureStatus"])) >= 2
	}
	return false
}

func hasMultiSignal(entry timelineEntry) bool {
	signals := map[string]bool{}
	for _, flag := range entry.ReasonFlags {
		if flag != "" {
			signals[flag] = true
		}
	}
	if strings.Contains(strings.ToLower(stringFromAny(entry.Metadata["signatureStatus"])), "unsigned") {
		signals["unsigned_signature"] = true
	}
	if strings.Contains(strings.ToLower(entry.Path), `\users\***`) {
		signals["user_path"] = true
	}
	return len(signals) >= 2
}

func isRobloxName(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "robloxplayerbeta") || strings.Contains(lower, "robloxstudiobeta") || strings.Contains(lower, "robloxcrashhandler")
}

func nearAny(entry timelineEntry, others []timelineEntry, window time.Duration) bool {
	for _, other := range others {
		if nearTime(entry, other, window) {
			return true
		}
	}
	return false
}

func nearestEntry(entry timelineEntry, others []timelineEntry) timelineEntry {
	if len(others) == 0 {
		return timelineEntry{}
	}
	best := others[0]
	bestDistance := time.Duration(1<<63 - 1)
	for _, other := range others {
		if !entry.HasTime || !other.HasTime {
			continue
		}
		distance := entry.When.Sub(other.When)
		if distance < 0 {
			distance = -distance
		}
		if distance < bestDistance {
			bestDistance = distance
			best = other
		}
	}
	return best
}

func nearTime(a timelineEntry, b timelineEntry, window time.Duration) bool {
	if !a.HasTime || !b.HasTime {
		return false
	}
	delta := a.When.Sub(b.When)
	if delta < 0 {
		delta = -delta
	}
	return delta <= window
}

func sameSubjectFamily(a timelineEntry, b timelineEntry) bool {
	aKey := artifactSubjectKey(a)
	bKey := artifactSubjectKey(b)
	return aKey != "" && bKey != "" && aKey == bKey
}

func artifactSubjectKey(entry timelineEntry) string {
	for _, value := range []string{entry.Path, entry.Subject, entry.ProcessName, entry.Title} {
		base := strings.ToLower(strings.TrimSpace(value))
		if base == "" || base == "unknown" {
			continue
		}
		base = strings.ReplaceAll(base, "/", `\`)
		if strings.Contains(base, `\`) {
			base = base[strings.LastIndex(base, `\`)+1:]
		}
		base = strings.TrimSpace(base)
		if base != "" && base != "***" {
			return base
		}
	}
	return ""
}

func filterEntries(entries []timelineEntry, keep func(timelineEntry) bool) []timelineEntry {
	out := []timelineEntry{}
	for _, entry := range entries {
		if keep(entry) {
			out = append(out, entry)
		}
	}
	return out
}

func containsAnyFlag(flags []string, values []string) bool {
	for _, flag := range flags {
		lower := strings.ToLower(flag)
		for _, value := range values {
			if strings.Contains(lower, strings.ToLower(value)) {
				return true
			}
		}
	}
	return false
}

func collectEntryFlags(entries []timelineEntry) []string {
	flags := []string{}
	for _, entry := range entries {
		flags = append(flags, entry.ReasonFlags...)
	}
	return uniqueStringsSorted(flags)
}

func dedupeCorrelationGroups(groups []correlationGroup) []correlationGroup {
	seen := map[string]correlationGroup{}
	for _, group := range groups {
		if len(group.SourceModules) < 1 || len(group.TimelineIDs) < 1 {
			continue
		}
		key := group.ID
		if _, exists := seen[key]; !exists {
			seen[key] = group
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]correlationGroup, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}

func countTimelineStringField(rows []map[string]any, key string) map[string]int {
	out := map[string]int{}
	for _, row := range rows {
		value := stringFromAny(row[key])
		if value == "" {
			value = "unknown"
		}
		out[value]++
	}
	return out
}

func topCorrelationTitles(groups []correlationGroup, limit int) []string {
	titles := []string{}
	for _, group := range groups {
		titles = append(titles, group.Title)
		if len(titles) >= limit {
			break
		}
	}
	return titles
}
