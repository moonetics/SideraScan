package windows

import (
	"path/filepath"
	"strings"
)

func MatchBuiltInUtility(name string, path string) RuleMatch {
	lowerName := strings.ToLower(strings.TrimSpace(name))
	lowerBase := strings.ToLower(filepath.Base(lowerName))
	lowerPath := strings.ToLower(strings.TrimSpace(path))

	for _, rule := range builtInUtilityRules {
		for _, candidate := range rule.ProcessNames {
			candidate = strings.ToLower(candidate)
			if lowerName == candidate || lowerBase == candidate {
				return rule.toMatch()
			}
		}

		searchTarget := lowerName + " " + lowerPath
		for _, needle := range rule.Contains {
			if strings.Contains(searchTarget, strings.ToLower(needle)) {
				return rule.toMatch()
			}
		}
	}

	return RuleMatch{}
}

func (rule utilityRule) toMatch() RuleMatch {
	return RuleMatch{
		Matched:    true,
		RuleID:     rule.ID,
		Category:   rule.Category,
		Status:     rule.Status,
		Severity:   rule.Severity,
		Confidence: rule.Confidence,
	}
}
