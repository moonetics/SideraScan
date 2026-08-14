package detections

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
	"github.com/moonetics/SideraScan/apps/scanner/internal/privacy"
)

const (
	RuleProcessName     = "PROCESS_NAME"
	RuleFileHash        = "FILE_HASH"
	RulePathPattern     = "PATH_PATTERN"
	RuleStringSignature = "STRING_SIGNATURE"

	DefaultCategory               = "CUSTOM_DETECTION"
	DefaultSeverity               = "WARNING"
	ExecutorIntelligenceManagedBy = "EXECUTOR_INTELLIGENCE"

	MaxStringScanFileBytes = 20 * 1024 * 1024
	MinPrintableStringLen  = 4
)

type Input struct {
	Rules                []contract.ScannerRule
	Payload              contract.UploadResultsRequest
	StringCandidateFiles []string
}

type Result struct {
	Findings         []contract.Finding
	EvaluatedRules   int
	MatchedRules     int
	InvalidRuleCount int
	PartialErrors    []string
}

type target struct {
	Kind        string
	Name        string
	Path        string
	Hash        string
	Source      string
	Metadata    map[string]any
	RawFilePath string
}

func Evaluate(ctx context.Context, input Input) Result {
	result := Result{}
	if len(input.Rules) == 0 {
		return result
	}

	targets := collectTargets(input)
	seenFindings := map[string]bool{}

	for _, rule := range input.Rules {
		select {
		case <-ctx.Done():
			result.PartialErrors = append(result.PartialErrors, "context_cancelled")
			return result
		default:
		}

		if strings.TrimSpace(rule.ID) == "" || strings.TrimSpace(rule.Type) == "" {
			result.InvalidRuleCount++
			continue
		}

		matches, err := evaluateRule(ctx, rule, targets)
		if err != nil {
			result.InvalidRuleCount++
			result.PartialErrors = append(result.PartialErrors, safeRuleError(rule, err))
			continue
		}
		result.EvaluatedRules++
		if len(matches) > 0 {
			result.MatchedRules++
		}

		for _, matched := range matches {
			key := rule.ID + ":" + matched.Kind + ":" + matched.Name + ":" + matched.Path + ":" + matched.Hash
			if seenFindings[key] {
				continue
			}
			seenFindings[key] = true
			result.Findings = append(result.Findings, findingForMatch(rule, matched))
		}
	}

	return result
}

func evaluateRule(ctx context.Context, rule contract.ScannerRule, targets []target) ([]target, error) {
	switch strings.ToUpper(strings.TrimSpace(rule.Type)) {
	case RuleProcessName:
		config, err := parseProcessNameConfig(rule.RuleConfig)
		if err != nil {
			return nil, err
		}
		return matchNameTargets(targets, "process", config.ProcessNames, config.MatchMode)
	case RulePathPattern:
		config, err := parsePathPatternConfig(rule.RuleConfig)
		if err != nil {
			return nil, err
		}
		return matchPathTargets(targets, config.Patterns, config.MatchMode)
	case RuleFileHash:
		config, err := parseFileHashConfig(rule.RuleConfig)
		if err != nil {
			return nil, err
		}
		return matchHashTargets(targets, config.Hashes), nil
	case RuleStringSignature:
		config, err := parseStringSignatureConfig(rule.RuleConfig)
		if err != nil {
			return nil, err
		}
		return matchStringTargets(ctx, targets, config)
	default:
		return nil, fmt.Errorf("unsupported rule type")
	}
}

type processNameConfig struct {
	ProcessNames []string
	MatchMode    string
}

type fileHashConfig struct {
	Hashes    []string
	Algorithm string
}

type pathPatternConfig struct {
	Patterns  []string
	MatchMode string
}

type stringSignatureConfig struct {
	Strings            []stringSignature
	TargetProcessNames []string
	ClientName         string
}

type stringSignature struct {
	ValueHash string
	Preview   string
}

func parseProcessNameConfig(config map[string]any) (processNameConfig, error) {
	out := processNameConfig{
		ProcessNames: stringsFromAny(config["processNames"]),
		MatchMode:    strings.ToLower(stringFromAny(config["matchMode"])),
	}
	if len(out.ProcessNames) == 0 || !validMatchMode(out.MatchMode, "exact", "contains", "regex") {
		return out, errors.New("invalid process name config")
	}
	return out, nil
}

func parseFileHashConfig(config map[string]any) (fileHashConfig, error) {
	out := fileHashConfig{
		Hashes:    lowerStrings(stringsFromAny(config["hashes"])),
		Algorithm: strings.ToLower(stringFromAny(config["algorithm"])),
	}
	if len(out.Hashes) == 0 || out.Algorithm != "sha256" {
		return out, errors.New("invalid file hash config")
	}
	return out, nil
}

func parsePathPatternConfig(config map[string]any) (pathPatternConfig, error) {
	out := pathPatternConfig{
		Patterns:  stringsFromAny(config["patterns"]),
		MatchMode: strings.ToLower(stringFromAny(config["matchMode"])),
	}
	if len(out.Patterns) == 0 || !validMatchMode(out.MatchMode, "contains", "glob", "regex") {
		return out, errors.New("invalid path pattern config")
	}
	return out, nil
}

func parseStringSignatureConfig(config map[string]any) (stringSignatureConfig, error) {
	out := stringSignatureConfig{
		TargetProcessNames: stringsFromAny(config["targetProcessNames"]),
		ClientName:         stringFromAny(config["clientName"]),
	}
	for _, item := range anySlice(config["strings"]) {
		mapping, ok := item.(map[string]any)
		if !ok {
			continue
		}
		valueHash := strings.ToLower(strings.TrimSpace(stringFromAny(mapping["valueHash"])))
		if valueHash == "" {
			continue
		}
		out.Strings = append(out.Strings, stringSignature{
			ValueHash: valueHash,
			Preview:   stringFromAny(mapping["preview"]),
		})
	}
	if len(out.Strings) == 0 {
		return out, errors.New("invalid string signature config")
	}
	return out, nil
}

func matchNameTargets(targets []target, kind string, patterns []string, mode string) ([]target, error) {
	matches := []target{}
	for _, target := range targets {
		if target.Kind != kind {
			continue
		}
		if matchesAny(target.Name, patterns, mode) {
			matches = append(matches, target)
		}
	}
	return matches, nil
}

func matchPathTargets(targets []target, patterns []string, mode string) ([]target, error) {
	matches := []target{}
	for _, target := range targets {
		if strings.TrimSpace(target.Path) == "" {
			continue
		}
		if matchesAny(target.Path, patterns, mode) {
			matches = append(matches, target)
		}
	}
	return matches, nil
}

func matchHashTargets(targets []target, hashes []string) []target {
	allowed := map[string]bool{}
	for _, hash := range hashes {
		allowed[strings.ToLower(strings.TrimSpace(hash))] = true
	}

	matches := []target{}
	for _, target := range targets {
		hash := strings.ToLower(strings.TrimSpace(target.Hash))
		if hash != "" && allowed[hash] {
			matches = append(matches, target)
		}
	}
	return matches
}

func matchStringTargets(ctx context.Context, targets []target, config stringSignatureConfig) ([]target, error) {
	expected := map[string]bool{}
	for _, item := range config.Strings {
		expected[strings.ToLower(strings.TrimSpace(item.ValueHash))] = true
	}

	matches := []target{}
	errs := []string{}
	for _, target := range targets {
		if target.RawFilePath == "" {
			continue
		}
		if !stringTargetAllowed(target, config) {
			continue
		}
		matched, err := fileContainsStringHash(ctx, target.RawFilePath, expected)
		if err != nil {
			errs = append(errs, target.Kind)
			continue
		}
		if matched {
			target.Hash = ""
			target.Metadata = mergeMetadata(target.Metadata, map[string]any{
				"stringRuleMatched": true,
				"stringHashCount":   len(expected),
			})
			matches = append(matches, target)
		}
	}

	if len(errs) > 0 && len(matches) == 0 {
		return matches, errors.New("string scan partial")
	}

	return matches, nil
}

func stringTargetAllowed(target target, config stringSignatureConfig) bool {
	if len(config.TargetProcessNames) > 0 && !matchesAny(filepath.Base(target.RawFilePath), config.TargetProcessNames, "exact") && !matchesAny(target.Name, config.TargetProcessNames, "exact") {
		return false
	}
	if strings.TrimSpace(config.ClientName) != "" {
		needle := strings.ToLower(strings.TrimSpace(config.ClientName))
		contextText := strings.ToLower(target.Name + " " + target.Path + " " + target.Source)
		if !strings.Contains(contextText, needle) {
			return false
		}
	}
	return true
}

func fileContainsStringHash(ctx context.Context, filePath string, expected map[string]bool) (bool, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return false, err
	}
	if info.IsDir() || info.Size() <= 0 || info.Size() > MaxStringScanFileBytes {
		return false, errors.New("file not eligible")
	}

	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	buffer := make([]byte, 0, 256)
	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}

		item, err := reader.ReadByte()
		if err != nil && !errors.Is(err, io.EOF) {
			return false, err
		}

		if err == nil && isPrintableASCII(item) {
			buffer = append(buffer, item)
			continue
		}

		if len(buffer) >= MinPrintableStringLen {
			sum := sha256.Sum256(buffer)
			if expected[hex.EncodeToString(sum[:])] {
				return true, nil
			}
		}
		buffer = buffer[:0]

		if errors.Is(err, io.EOF) {
			break
		}
	}

	return false, nil
}

func isPrintableASCII(value byte) bool {
	return value >= 32 && value <= 126
}

func collectTargets(input Input) []target {
	targets := []target{}

	for _, row := range input.Payload.ProcessTimeline {
		targets = append(targets, target{
			Kind:   "process",
			Name:   stringValue(row, "processName"),
			Path:   stringValue(row, "path"),
			Source: stringValue(row, "source"),
			Metadata: map[string]any{
				"pid":             row["pid"],
				"status":          row["status"],
				"signatureStatus": row["signatureStatus"],
				"suspiciousFlags": row["suspiciousFlags"],
				"reasonFlags":     row["reasonFlags"],
				"source":          row["source"],
			},
		})
	}

	for _, profile := range input.Payload.LauncherProfiles {
		targets = append(targets, target{
			Kind:   "launcher_profile",
			Name:   profile.ProfileName,
			Path:   profile.Path,
			Hash:   profile.ExecutableHash,
			Source: profile.LauncherType,
			Metadata: map[string]any{
				"status": profile.Status,
			},
		})
	}

	for _, asset := range input.Payload.ClientModAssets {
		targets = append(targets, target{
			Kind:   "client_mod_asset",
			Name:   asset.Name,
			Path:   asset.Path,
			Source: asset.SourceLauncher,
			Metadata: map[string]any{
				"status": asset.Status,
			},
		})
	}

	for _, process := range input.Payload.ProcessTimes {
		targets = append(targets, target{
			Kind:   "process_time",
			Name:   process.ProcessName,
			Path:   process.Path,
			Source: process.Source,
			Metadata: map[string]any{
				"status": process.Status,
			},
		})
	}

	for _, fileLog := range input.Payload.FileLogs {
		targets = append(targets, target{
			Kind:   "file_log",
			Name:   fileLog.Action,
			Path:   firstNonEmpty(fileLog.Path, fileLog.NewPath, fileLog.OldPath),
			Source: fileLog.Source,
			Metadata: map[string]any{
				"action":         fileLog.Action,
				"relatedProcess": fileLog.RelatedProcess,
				"severity":       fileLog.Severity,
			},
		})
	}

	for _, row := range input.Payload.Utilities {
		targets = append(targets, target{
			Kind:   "utility",
			Name:   stringValue(row, "processName"),
			Path:   stringValue(row, "path"),
			Hash:   stringValue(row, "executableSha256"),
			Source: stringValue(row, "source"),
			Metadata: map[string]any{
				"category":    row["category"],
				"matchedRule": row["matchedRule"],
				"status":      row["status"],
			},
		})
	}

	for _, row := range input.Payload.WindowsItems {
		targets = append(targets, target{
			Kind:   "windows_item",
			Name:   stringValue(row, "name"),
			Path:   stringValue(row, "path"),
			Source: stringValue(row, "source"),
			Metadata: map[string]any{
				"kind":   row["kind"],
				"status": row["status"],
			},
		})
	}

	appendMapTargets := func(kind string, rows []map[string]any, nameKeys []string, pathKeys []string, hashKeys []string) {
		for _, row := range rows {
			name := firstStringValue(row, nameKeys...)
			pathValue := firstStringValue(row, pathKeys...)
			hash := firstStringValue(row, hashKeys...)
			targets = append(targets, target{
				Kind:   kind,
				Name:   name,
				Path:   pathValue,
				Hash:   hash,
				Source: firstStringValue(row, "source", "sourceModule", "artifactType"),
				Metadata: map[string]any{
					"status":          row["status"],
					"severity":        row["severity"],
					"signatureStatus": row["signatureStatus"],
					"suspiciousFlags": row["suspiciousFlags"],
					"reasonFlags":     row["reasonFlags"],
					"action":          row["action"],
					"processName":     row["processName"],
					"targetProcess":   row["targetProcessName"],
				},
			})
		}
	}

	appendMapTargets("loaded_module", input.Payload.LoadedModules, []string{"moduleName", "name"}, []string{"path"}, []string{"sha256", "hash"})
	appendMapTargets("process_handle", input.Payload.ProcessHandles, []string{"sourceProcessName", "processName"}, []string{"sourcePath", "path"}, []string{"sha256", "hash"})
	appendMapTargets("service", input.Payload.Services, []string{"name", "displayName"}, []string{"imagePath", "path", "command"}, []string{"sha256", "hash"})
	appendMapTargets("driver", input.Payload.Drivers, []string{"driverName", "name"}, []string{"imagePath", "path"}, []string{"sha256", "hash"})
	appendMapTargets("persistence", input.Payload.PersistenceItems, []string{"name", "valueName", "entryName"}, []string{"path", "command", "imagePath"}, []string{"sha256", "hash"})
	appendMapTargets("execution_artifact", input.Payload.ExecutionArtifacts, []string{"name", "title", "relatedExecutable"}, []string{"path"}, []string{"sha256", "hash"})
	appendMapTargets("file_triage", input.Payload.FileTriage, []string{"filename", "name"}, []string{"path"}, []string{"sha256", "hash"})
	appendMapTargets("network_connection", input.Payload.NetworkConnections, []string{"processName", "remoteAddress"}, []string{"processPath", "path"}, []string{"sha256", "hash"})
	appendMapTargets("forensic_timeline", input.Payload.ForensicTimeline, []string{"title", "subject", "processName"}, []string{"path"}, []string{"sha256", "hash"})

	for _, filePath := range uniqueStrings(input.StringCandidateFiles) {
		targets = append(targets, target{
			Kind:        "string_candidate_file",
			Name:        filepath.Base(filePath),
			Path:        privacy.MaskPath(filePath),
			Source:      "safe_scope_file",
			RawFilePath: filePath,
		})
	}

	return targets
}

func findingForMatch(rule contract.ScannerRule, matched target) contract.Finding {
	if isExecutorIntelligenceRule(rule) {
		return executorIntelligenceFinding(rule, matched)
	}

	category := firstNonEmpty(rule.Category, DefaultCategory)
	severity := firstNonEmpty(rule.Severity, DefaultSeverity)
	metadata := privacy.RedactMap(map[string]any{
		"ruleType":      rule.Type,
		"ruleName":      rule.Name,
		"matchedKind":   matched.Kind,
		"matchedName":   matched.Name,
		"matchedPath":   matched.Path,
		"hashPrefix":    shortHash(matched.Hash),
		"targetSource":  matched.Source,
		"targetDetails": matched.Metadata,
	})
	return contract.Finding{
		Category:     category,
		Severity:     severity,
		Title:        "Custom detection matched: " + firstNonEmpty(rule.Name, rule.ID),
		Message:      "A configured custom detection rule matched scoped scanner metadata.",
		RuleID:       rule.ID,
		Confidence:   85,
		SourceModule: "custom_detections",
		Metadata:     metadata,
	}
}

func isExecutorIntelligenceRule(rule contract.ScannerRule) bool {
	if strings.EqualFold(rule.ManagedBy, ExecutorIntelligenceManagedBy) {
		return true
	}
	return strings.EqualFold(stringFromAny(rule.RuleConfig["managedBy"]), ExecutorIntelligenceManagedBy)
}

func executorIntelligenceFinding(rule contract.ScannerRule, matched target) contract.Finding {
	signals := executorWarningSignals(matched)
	severity := "INFO"
	confidence := 68
	if len(signals) >= 2 {
		severity = "WARNING"
		confidence = 86
	}

	executorName := firstNonEmpty(stringFromAny(rule.RuleConfig["executorName"]), rule.Name, rule.ID)
	metadata := privacy.RedactMap(map[string]any{
		"ruleType":           rule.Type,
		"ruleName":           rule.Name,
		"managedBy":          ExecutorIntelligenceManagedBy,
		"intelligenceSource": stringFromAny(rule.RuleConfig["sourceName"]),
		"executorName":       executorName,
		"executorType":       stringFromAny(rule.RuleConfig["executorType"]),
		"detected":           rule.RuleConfig["detected"],
		"updateStatus":       rule.RuleConfig["updateStatus"],
		"feedUpdatedAt":      rule.RuleConfig["feedUpdatedAt"],
		"reviewOnly":         len(signals) < 2,
		"matchedKind":        matched.Kind,
		"matchedName":        matched.Name,
		"matchedPath":        matched.Path,
		"hashPrefix":         shortHash(matched.Hash),
		"targetSource":       matched.Source,
		"targetDetails":      matched.Metadata,
		"warningSignalCount": len(signals),
		"warningSignals":     signals,
	})

	return contract.Finding{
		Category:     firstNonEmpty(rule.Category, DefaultCategory),
		Severity:     severity,
		Title:        "Executor intelligence match: " + executorName,
		Message:      "A managed executor intelligence rule matched scoped scanner metadata. Name-only matches are advisory unless supporting signals are present.",
		RuleID:       rule.ID,
		Confidence:   confidence,
		SourceModule: "executor_intelligence",
		Metadata:     metadata,
	}
}

func executorWarningSignals(matched target) []string {
	signals := []string{}
	text := strings.ToLower(strings.Join([]string{
		matched.Kind,
		matched.Name,
		matched.Path,
		matched.Source,
		metadataText(matched.Metadata),
	}, " "))

	if strings.Contains(text, "\\temp\\") ||
		strings.Contains(text, "/temp/") ||
		strings.Contains(text, "downloads") ||
		strings.Contains(text, "appdata") ||
		strings.Contains(text, "discord") ||
		strings.Contains(text, "telegram") {
		signals = append(signals, "user_writable_or_download_path")
	}

	if strings.Contains(text, "unsigned") ||
		strings.Contains(text, "invalid_signature") ||
		strings.Contains(text, "untrusted_signature") {
		signals = append(signals, "unsigned_or_untrusted")
	}

	if strings.Contains(text, "roblox") {
		signals = append(signals, "roblox_correlation")
	}

	if matched.Kind == "persistence" ||
		matched.Kind == "service" ||
		matched.Kind == "driver" ||
		strings.Contains(text, "defender_exclusion") ||
		strings.Contains(text, "persistence") {
		signals = append(signals, "persistence_or_defender_context")
	}

	if matched.Kind == "file_log" ||
		matched.Kind == "execution_artifact" ||
		strings.Contains(text, "downloaded") ||
		strings.Contains(text, "executed") ||
		strings.Contains(text, "deleted") {
		signals = append(signals, "download_execute_delete_chain")
	}

	if strings.Contains(text, "suspicious") ||
		strings.Contains(text, "warning") ||
		strings.Contains(text, "severe") {
		signals = append(signals, "suspicious_artifact_context")
	}

	return uniqueStrings(signals)
}

func matchesAny(value string, patterns []string, mode string) bool {
	for _, pattern := range patterns {
		if matchValue(value, pattern, mode) {
			return true
		}
	}
	return false
}

func matchValue(value string, patternValue string, mode string) bool {
	value = strings.TrimSpace(value)
	patternValue = strings.TrimSpace(patternValue)
	if value == "" || patternValue == "" {
		return false
	}

	switch strings.ToLower(mode) {
	case "exact":
		return strings.EqualFold(value, patternValue)
	case "contains":
		return strings.Contains(strings.ToLower(value), strings.ToLower(patternValue))
	case "glob":
		normalizedValue := normalizeGlob(value)
		normalizedPattern := normalizeGlob(patternValue)
		if matchGlob(normalizedPattern, normalizedValue) {
			return true
		}
		return matchGlob(normalizedPattern, path.Base(normalizedValue))
	case "regex":
		compiled, err := regexp.Compile(patternValue)
		if err != nil {
			return false
		}
		return compiled.MatchString(value)
	default:
		return false
	}
}

func normalizeGlob(value string) string {
	return strings.ToLower(strings.ReplaceAll(filepath.ToSlash(value), "\\", "/"))
}

func matchGlob(patternValue string, value string) bool {
	matched, err := path.Match(patternValue, value)
	if err == nil && matched {
		return true
	}

	var builder strings.Builder
	builder.WriteString("^")
	for _, char := range patternValue {
		switch char {
		case '*':
			builder.WriteString(".*")
		case '?':
			builder.WriteString(".")
		default:
			builder.WriteString(regexp.QuoteMeta(string(char)))
		}
	}
	builder.WriteString("$")
	compiled, err := regexp.Compile(builder.String())
	if err != nil {
		return false
	}
	return compiled.MatchString(value)
}

func validMatchMode(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func stringsFromAny(value any) []string {
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

func anySlice(value any) []any {
	switch typed := value.(type) {
	case []any:
		return typed
	default:
		return nil
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

func stringValue(row map[string]any, key string) string {
	return stringFromAny(row[key])
}

func firstStringValue(row map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringValue(row, key); value != "" {
			return value
		}
	}
	return ""
}

func metadataText(metadata map[string]any) string {
	parts := []string{}
	for key, value := range metadata {
		parts = append(parts, key)
		switch typed := value.(type) {
		case string:
			parts = append(parts, typed)
		case []string:
			parts = append(parts, typed...)
		case []any:
			for _, item := range typed {
				if text := stringFromAny(item); text != "" {
					parts = append(parts, text)
				}
			}
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

func lowerStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strings.ToLower(strings.TrimSpace(value)))
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(filepath.Clean(value))
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func mergeMetadata(base map[string]any, extra map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range base {
		out[key] = value
	}
	for key, value := range extra {
		out[key] = value
	}
	return out
}

func safeRuleError(rule contract.ScannerRule, err error) string {
	return strings.ToLower(strings.TrimSpace(rule.Type)) + ":" + err.Error()
}

func shortHash(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
