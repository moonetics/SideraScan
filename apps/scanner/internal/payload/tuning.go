package payload

import (
	"fmt"
	"sort"
	"strings"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

var forensicSectionsForSummary = []struct {
	name string
	rows func(*contract.UploadResultsRequest) []map[string]any
}{
	{"processTimeline", func(r *contract.UploadResultsRequest) []map[string]any { return r.ProcessTimeline }},
	{"loadedModules", func(r *contract.UploadResultsRequest) []map[string]any { return r.LoadedModules }},
	{"processHandles", func(r *contract.UploadResultsRequest) []map[string]any { return r.ProcessHandles }},
	{"services", func(r *contract.UploadResultsRequest) []map[string]any { return r.Services }},
	{"drivers", func(r *contract.UploadResultsRequest) []map[string]any { return r.Drivers }},
	{"persistenceItems", func(r *contract.UploadResultsRequest) []map[string]any { return r.PersistenceItems }},
	{"eventLogs", func(r *contract.UploadResultsRequest) []map[string]any { return r.EventLogs }},
	{"defenderEvents", func(r *contract.UploadResultsRequest) []map[string]any { return r.DefenderEvents }},
	{"executionArtifacts", func(r *contract.UploadResultsRequest) []map[string]any { return r.ExecutionArtifacts }},
	{"fileTriage", func(r *contract.UploadResultsRequest) []map[string]any { return r.FileTriage }},
	{"networkConnections", func(r *contract.UploadResultsRequest) []map[string]any { return r.NetworkConnections }},
	{"dnsCache", func(r *contract.UploadResultsRequest) []map[string]any { return r.DNSCache }},
	{"hostsEntries", func(r *contract.UploadResultsRequest) []map[string]any { return r.HostsEntries }},
	{"forensicTimeline", func(r *contract.UploadResultsRequest) []map[string]any { return r.ForensicTimeline }},
}

func ApplyForensicNoiseTuning(request *contract.UploadResultsRequest) {
	if request == nil {
		return
	}
	if request.Integrity == nil {
		request.Integrity = map[string]any{}
	}
	before := len(request.Findings)
	request.Findings = dedupeFindings(request.Findings)
	scoreContributors := map[string]int{}
	for _, finding := range request.Findings {
		key := strings.ToLower(strings.TrimSpace(finding.SourceModule))
		if key == "" {
			key = "unknown"
		}
		scoreContributors[key+"."+strings.ToUpper(strings.TrimSpace(finding.Severity))]++
	}

	sectionCounts := map[string]any{}
	noiseSuppressed := 0
	benign := 0
	reviewOnly := 0
	for _, section := range forensicSectionsForSummary {
		rows := section.rows(request)
		counts := map[string]int{"total": len(rows)}
		for _, row := range rows {
			status := strings.ToLower(fmt.Sprint(row["status"]))
			severity := strings.ToUpper(fmt.Sprint(row["severity"]))
			flags := strings.ToLower(fmt.Sprint(firstPresent(row, "reasonFlags", "suspiciousFlags")))
			if status == "context" || (severity == "INFO" && (status == "review" || strings.Contains(flags, "historical_artifact_context"))) {
				noiseSuppressed++
				counts["context"]++
			}
			if strings.Contains(flags, "benign_") || strings.Contains(flags, "known_overlay") {
				benign++
				counts["benign"]++
			}
			if status == "review" && severity == "INFO" {
				reviewOnly++
				counts["reviewOnly"]++
			}
			if severity == "WARNING" || severity == "SEVERE" || severity == "CRITICAL" {
				counts["warningOrHigher"]++
			}
		}
		if len(rows) > 0 {
			sectionCounts[section.name] = counts
		}
	}

	request.Integrity["af8Summary"] = map[string]any{
		"noiseSuppressedCount":  noiseSuppressed,
		"benignClassifiedCount": benign,
		"reviewOnlyCount":       reviewOnly,
		"dedupedFindings":       before - len(request.Findings),
		"scoreContributors":     scoreContributors,
		"sectionCounts":         sectionCounts,
		"severityPolicy":        "warning_requires_strong_or_multi_signal",
		"singleArtifactContext": true,
	}
}

func dedupeFindings(findings []contract.Finding) []contract.Finding {
	seen := map[string]contract.Finding{}
	keys := []string{}
	for _, finding := range findings {
		key := findingDedupeKey(finding)
		if existing, ok := seen[key]; ok {
			if severityRank(finding.Severity) > severityRank(existing.Severity) {
				seen[key] = finding
			}
			continue
		}
		seen[key] = finding
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]contract.Finding, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}

func findingDedupeKey(finding contract.Finding) string {
	target := ""
	for _, key := range []string{"path", "sourcePath", "processName", "moduleName", "name", "host", "correlationId"} {
		if value, ok := finding.Metadata[key]; ok && strings.TrimSpace(fmt.Sprint(value)) != "" {
			target = fmt.Sprint(value)
			break
		}
	}
	if target == "" {
		target = finding.EvidenceRef
	}
	return strings.ToLower(strings.Join([]string{
		finding.SourceModule,
		finding.RuleID,
		finding.Title,
		target,
		fmt.Sprint(finding.Metadata["suspiciousFlags"]),
		fmt.Sprint(finding.Metadata["reasonFlags"]),
	}, "|"))
}

func firstPresent(row map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := row[key]; ok {
			return value
		}
	}
	return nil
}

func severityRank(value string) int {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "CRITICAL":
		return 4
	case "SEVERE":
		return 3
	case "WARNING":
		return 2
	case "INFO", "CLEAN":
		return 1
	default:
		return 0
	}
}
