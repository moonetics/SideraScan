package scannerconfig

import (
	"errors"
	"strings"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

var ErrAccountMismatch = errors.New("scanner config account mismatch")

type Validation struct {
	Config   contract.ScannerConfigResponse
	Partial  bool
	Warnings []string
}

func ValidateResponse(session contract.ScannerSession, response contract.ScannerConfigResponse, scannerVersion string) (Validation, error) {
	out := Validation{Config: response}
	out.Config.AdvancedForensics = normalizeAdvancedForensics(response.AdvancedForensics)

	if strings.TrimSpace(response.AccountID) != "" &&
		strings.TrimSpace(session.AccountID) != "" &&
		response.AccountID != session.AccountID {
		return out, ErrAccountMismatch
	}

	if strings.TrimSpace(response.Status) != "" && !strings.EqualFold(response.Status, "ok") {
		out.Partial = true
		out.Warnings = append(out.Warnings, "config_status_not_ok")
		out.Config.Rules = nil
		return out, nil
	}

	if strings.TrimSpace(response.ScannerVersion) != "" &&
		strings.TrimSpace(scannerVersion) != "" &&
		response.ScannerVersion != scannerVersion {
		out.Partial = true
		out.Warnings = append(out.Warnings, "config_version_mismatch")
		out.Config.Rules = nil
		return out, nil
	}

	rules := make([]contract.ScannerRule, 0, len(response.Rules))
	for _, rule := range response.Rules {
		if validRule(rule) {
			rules = append(rules, rule)
			continue
		}
		out.Partial = true
		out.Warnings = append(out.Warnings, "invalid_rule_skipped")
	}
	out.Config.Rules = rules

	return out, nil
}

func normalizeAdvancedForensics(config contract.AdvancedForensicsConfig) contract.AdvancedForensicsConfig {
	if config.MaxRowsPerModule <= 0 {
		config.MaxRowsPerModule = 250
	}
	if config.MaxFileHashMB <= 0 {
		config.MaxFileHashMB = 100
	}
	if config.MaxPayloadBytes <= 0 {
		config.MaxPayloadBytes = 24 * 1024 * 1024
	}
	if config.MaxTimelineRows <= 0 {
		config.MaxTimelineRows = 350
	}
	switch strings.ToLower(strings.TrimSpace(config.ReviewMode)) {
	case "ai_assisted_full":
		config.ReviewMode = "ai_assisted_full"
	default:
		config.ReviewMode = "review_relevant_only"
	}
	if !config.Enabled {
		config.Modules = contract.AdvancedForensicsModules{}
		config.BrowserDownloadHistory = false
		config.DiscordTelegramMetadata = false
		config.ReviewMode = "review_relevant_only"
	}
	return config
}

func validRule(rule contract.ScannerRule) bool {
	if strings.TrimSpace(rule.ID) == "" ||
		strings.TrimSpace(rule.Name) == "" ||
		strings.TrimSpace(rule.Type) == "" ||
		strings.TrimSpace(rule.Category) == "" ||
		strings.TrimSpace(rule.Severity) == "" {
		return false
	}

	switch strings.ToUpper(strings.TrimSpace(rule.Type)) {
	case "PROCESS_NAME":
		return len(stringsFromAny(rule.RuleConfig["processNames"])) > 0 &&
			validMatchMode(stringFromAny(rule.RuleConfig["matchMode"]), "exact", "contains", "regex")
	case "FILE_HASH":
		return len(stringsFromAny(rule.RuleConfig["hashes"])) > 0 &&
			strings.EqualFold(stringFromAny(rule.RuleConfig["algorithm"]), "sha256")
	case "PATH_PATTERN":
		return len(stringsFromAny(rule.RuleConfig["patterns"])) > 0 &&
			validMatchMode(stringFromAny(rule.RuleConfig["matchMode"]), "contains", "glob", "regex")
	case "STRING_SIGNATURE":
		for _, item := range anySlice(rule.RuleConfig["strings"]) {
			mapping, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if strings.TrimSpace(stringFromAny(mapping["valueHash"])) != "" {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func validMatchMode(value string, allowed ...string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func stringsFromAny(value any) []string {
	out := []string{}
	switch typed := value.(type) {
	case []string:
		for _, item := range typed {
			if strings.TrimSpace(item) != "" {
				out = append(out, item)
			}
		}
	case []any:
		for _, item := range typed {
			if text := stringFromAny(item); text != "" {
				out = append(out, text)
			}
		}
	}
	return out
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
