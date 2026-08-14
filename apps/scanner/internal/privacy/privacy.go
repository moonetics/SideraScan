package privacy

import (
	"regexp"
	"strings"
)

var (
	windowsUserPath = regexp.MustCompile(`(?i)([A-Z]:[\\/]+Users[\\/]+)([^\\/]+)`)
	unixUserPath    = regexp.MustCompile(`(?i)(/Users/)([^/]+)`)
)

func MaskPath(value string) string {
	value = windowsUserPath.ReplaceAllString(value, `${1}***`)
	value = unixUserPath.ReplaceAllString(value, `${1}***`)

	return value
}

func RedactString(value string) string {
	if value == "" {
		return value
	}

	lower := strings.ToLower(value)
	sensitiveMarkers := []string{
		"machineguid",
		"machine guid",
		"serialnumber",
		"serial number",
		"scannerkey",
		"scanner key",
		"uploadtoken",
		"upload token",
		"password",
		"clipboard",
		"cookie",
		"screenshot",
		"nonce",
		"token",
	}

	for _, marker := range sensitiveMarkers {
		if strings.Contains(lower, marker) {
			return "[REDACTED]"
		}
	}

	return MaskPath(value)
}

func RedactMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}

	output := make(map[string]any, len(input))
	for key, value := range input {
		if isSensitiveKey(key) {
			output[key] = "[REDACTED]"
			continue
		}
		output[key] = RedactValue(value)
	}

	return output
}

func RedactValue(value any) any {
	switch typed := value.(type) {
	case string:
		return RedactString(typed)
	case map[string]any:
		return RedactMap(typed)
	case []string:
		clean := make([]string, 0, len(typed))
		for _, item := range typed {
			clean = append(clean, RedactString(item))
		}
		return clean
	case []any:
		clean := make([]any, 0, len(typed))
		for _, item := range typed {
			clean = append(clean, RedactValue(item))
		}
		return clean
	default:
		return value
	}
}

func isSensitiveKey(key string) bool {
	key = strings.ToLower(strings.ReplaceAll(key, "_", ""))
	markers := []string{
		"machineguid",
		"serial",
		"scannerkey",
		"uploadtoken",
		"password",
		"clipboard",
		"cookie",
		"screenshot",
		"nonce",
		"token",
	}
	for _, marker := range markers {
		if strings.Contains(key, marker) {
			return true
		}
	}

	return false
}
