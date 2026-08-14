package payload

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
	"github.com/moonetics/SideraScan/apps/scanner/internal/privacy"
)

const (
	DefaultMaxPayloadBytes = 24 * 1024 * 1024
	DefaultMaxTimelineRows = 350
)

type Budget struct {
	MaxPayloadBytes int
	MaxTimelineRows int
}

type CompactReport struct {
	OriginalSizeBytes int
	FinalSizeBytes    int
	BudgetBytes       int
	Trimmed           bool
	TrimmedSections   map[string]map[string]int
}

func SizeBytes(request contract.UploadResultsRequest) int {
	bytes, err := json.Marshal(request)
	if err != nil {
		return 0
	}
	return len(bytes)
}

func CompactForBudget(request *contract.UploadResultsRequest, budget Budget) CompactReport {
	if request == nil {
		return CompactReport{}
	}
	budget = normalizeBudget(budget)
	report := CompactReport{
		OriginalSizeBytes: SizeBytes(*request),
		BudgetBytes:       budget.MaxPayloadBytes,
		TrimmedSections:   map[string]map[string]int{},
	}
	if request.Integrity == nil {
		request.Integrity = map[string]any{}
	}

	compactTimelineMetadata(request)
	recordTrim(report.TrimmedSections, "forensicTimeline", len(request.ForensicTimeline), len(request.ForensicTimeline))

	if budget.MaxTimelineRows > 0 && len(request.ForensicTimeline) > budget.MaxTimelineRows {
		original := len(request.ForensicTimeline)
		request.ForensicTimeline = keepHighSignalRows(request.ForensicTimeline, budget.MaxTimelineRows)
		recordTrim(report.TrimmedSections, "forensicTimeline", original, len(request.ForensicTimeline))
	}

	for SizeBytes(*request) > budget.MaxPayloadBytes && len(request.ForensicTimeline) > 120 {
		original := len(request.ForensicTimeline)
		request.ForensicTimeline = keepHighSignalRows(request.ForensicTimeline, maxInt(120, len(request.ForensicTimeline)*70/100))
		recordTrim(report.TrimmedSections, "forensicTimeline", original, len(request.ForensicTimeline))
	}

	if SizeBytes(*request) > budget.MaxPayloadBytes {
		trimContextRows(report.TrimmedSections, "dnsCache", &request.DNSCache, 40)
		trimContextRows(report.TrimmedSections, "hostsEntries", &request.HostsEntries, 40)
		request.NetworkConnections = trimNetworkContext(report.TrimmedSections, request.NetworkConnections, 120)
	}

	if SizeBytes(*request) > budget.MaxPayloadBytes {
		trimContextRows(report.TrimmedSections, "executionArtifacts", &request.ExecutionArtifacts, 180)
		trimContextRows(report.TrimmedSections, "fileTriage", &request.FileTriage, 120)
	}

	report.FinalSizeBytes = SizeBytes(*request)
	report.Trimmed = report.FinalSizeBytes != report.OriginalSizeBytes || hasRealTrims(report.TrimmedSections)
	applyBudgetTelemetry(request, report)
	return report
}

func ForceCompact(request *contract.UploadResultsRequest, budget Budget) CompactReport {
	if request == nil {
		return CompactReport{}
	}
	budget = normalizeBudget(budget)
	report := CompactReport{
		OriginalSizeBytes: SizeBytes(*request),
		BudgetBytes:       budget.MaxPayloadBytes,
		TrimmedSections:   map[string]map[string]int{},
	}
	if request.Integrity == nil {
		request.Integrity = map[string]any{}
	}

	compactTimelineMetadata(request)
	if len(request.ForensicTimeline) > 100 {
		original := len(request.ForensicTimeline)
		request.ForensicTimeline = keepHighSignalRows(request.ForensicTimeline, 100)
		recordTrim(report.TrimmedSections, "forensicTimeline", original, len(request.ForensicTimeline))
	}
	trimContextRows(report.TrimmedSections, "dnsCache", &request.DNSCache, 25)
	trimContextRows(report.TrimmedSections, "hostsEntries", &request.HostsEntries, 25)
	request.NetworkConnections = trimNetworkContext(report.TrimmedSections, request.NetworkConnections, 80)
	trimContextRows(report.TrimmedSections, "executionArtifacts", &request.ExecutionArtifacts, 120)
	trimContextRows(report.TrimmedSections, "fileTriage", &request.FileTriage, 90)

	report.FinalSizeBytes = SizeBytes(*request)
	report.Trimmed = report.FinalSizeBytes != report.OriginalSizeBytes || hasRealTrims(report.TrimmedSections)
	applyBudgetTelemetry(request, report)
	return report
}

func normalizeBudget(budget Budget) Budget {
	if budget.MaxPayloadBytes <= 0 {
		budget.MaxPayloadBytes = DefaultMaxPayloadBytes
	}
	if budget.MaxTimelineRows <= 0 {
		budget.MaxTimelineRows = DefaultMaxTimelineRows
	}
	return budget
}

func compactTimelineMetadata(request *contract.UploadResultsRequest) {
	for index, row := range request.ForensicTimeline {
		compact := map[string]any{}
		for _, key := range []string{
			"id", "timestamp", "timestampConfidence", "sourceModule", "eventType", "title",
			"subject", "path", "processName", "pid", "severity", "status", "confidence",
			"evidenceRefs", "correlationId", "reasonFlags",
		} {
			if value, ok := row[key]; ok {
				compact[key] = value
			}
		}
		request.ForensicTimeline[index] = privacy.RedactMap(compact)
	}
}

func keepHighSignalRows(rows []map[string]any, limit int) []map[string]any {
	if limit <= 0 || len(rows) <= limit {
		return rows
	}
	type scored struct {
		row   map[string]any
		index int
		score int
	}
	scoredRows := make([]scored, 0, len(rows))
	for index, row := range rows {
		scoredRows = append(scoredRows, scored{row: row, index: index, score: rowSignalScore(row)})
	}
	sort.SliceStable(scoredRows, func(i, j int) bool {
		if scoredRows[i].score != scoredRows[j].score {
			return scoredRows[i].score > scoredRows[j].score
		}
		return scoredRows[i].index < scoredRows[j].index
	})
	kept := scoredRows[:limit]
	sort.SliceStable(kept, func(i, j int) bool {
		return kept[i].index < kept[j].index
	})
	out := make([]map[string]any, 0, len(kept))
	for _, item := range kept {
		out = append(out, item.row)
	}
	return out
}

func rowSignalScore(row map[string]any) int {
	score := 0
	switch strings.ToUpper(stringFromAny(row["severity"])) {
	case "CRITICAL":
		score += 100
	case "SEVERE":
		score += 90
	case "WARNING":
		score += 70
	case "INFO":
		score += 25
	}
	switch strings.ToLower(stringFromAny(row["status"])) {
	case "suspicious", "flagged", "missing_file":
		score += 55
	case "review":
		score += 40
	case "context":
		score += 5
	}
	if strings.TrimSpace(stringFromAny(row["correlationId"])) != "" {
		score += 60
	}
	if len(stringsFromUnknown(row["evidenceRefs"])) > 0 {
		score += 40
	}
	score += minIntFromAny(row["confidence"], 100) / 5
	return score
}

func trimContextRows(trimmed map[string]map[string]int, section string, rows *[]map[string]any, limit int) {
	if rows == nil || len(*rows) <= limit {
		return
	}
	original := len(*rows)
	*rows = keepHighSignalRows(*rows, limit)
	recordTrim(trimmed, section, original, len(*rows))
}

func trimNetworkContext(trimmed map[string]map[string]int, rows []map[string]any, limit int) []map[string]any {
	if len(rows) <= limit {
		return rows
	}
	highSignal := []map[string]any{}
	contextRows := []map[string]any{}
	for _, row := range rows {
		source := strings.ToLower(stringFromAny(row["forensicSource"]) + " " + stringFromAny(row["source"]))
		if strings.Contains(source, "usb") || strings.EqualFold(stringFromAny(row["status"]), "context") {
			contextRows = append(contextRows, row)
			continue
		}
		highSignal = append(highSignal, row)
	}
	merged := append(highSignal, contextRows...)
	if len(merged) > limit {
		merged = keepHighSignalRows(merged, limit)
	}
	recordTrim(trimmed, "networkConnections", len(rows), len(merged))
	return merged
}

func recordTrim(trimmed map[string]map[string]int, section string, original int, uploaded int) {
	if original <= 0 {
		return
	}
	trimmed[section] = map[string]int{"original": original, "uploaded": uploaded}
}

func hasRealTrims(trimmed map[string]map[string]int) bool {
	for _, counts := range trimmed {
		if counts["uploaded"] < counts["original"] {
			return true
		}
	}
	return false
}

func applyBudgetTelemetry(request *contract.UploadResultsRequest, report CompactReport) {
	if request.Integrity == nil {
		request.Integrity = map[string]any{}
	}
	request.Integrity["payloadSizeBytes"] = report.FinalSizeBytes
	request.Integrity["payloadBudget"] = map[string]any{
		"maxPayloadBytes": report.BudgetBytes,
	}
	if report.Trimmed {
		request.Integrity["payloadTrimmed"] = true
		request.Integrity["trimmedSections"] = report.TrimmedSections
		request.Integrity["payloadOriginalSizeBytes"] = report.OriginalSizeBytes
	}
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	default:
		return ""
	}
}

func stringsFromUnknown(value any) []string {
	out := []string{}
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		for _, item := range typed {
			if text := stringFromAny(item); text != "" {
				out = append(out, text)
			}
		}
	}
	return out
}

func minIntFromAny(value any, fallback int) int {
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

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
