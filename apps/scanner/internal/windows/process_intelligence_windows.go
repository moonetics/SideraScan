//go:build windows

package windows

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unsafe"

	gopsnet "github.com/shirou/gopsutil/v4/net"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
	"github.com/moonetics/SideraScan/apps/scanner/internal/privacy"
)

const (
	maxNetworkSamplesPerProcess = 5
	maxSignatureChecksPerScan   = 40
)

var (
	commandSecretAssignment = regexp.MustCompile(`(?i)(--?(?:password|pass|pwd|token|key|secret|cookie|auth|session)[=:]\s*)(("[^"]*")|('[^']*')|[^\s]+)`)
	commandSecretSeparated  = regexp.MustCompile(`(?i)(--?(?:password|pass|pwd|token|key|secret|cookie|auth|session)\s+)(("[^"]*")|('[^']*')|[^\s]+)`)
	urlSecretQuery          = regexp.MustCompile(`(?i)([?&](?:password|pass|pwd|token|key|secret|cookie|auth|session)=)([^&\s]+)`)
	scannerSecretValue      = regexp.MustCompile(`(?i)(sds_live_[A-Za-z0-9-]+|sut_[A-Za-z0-9_-]+|snonce_[A-Za-z0-9_-]+)`)
	randomHexName           = regexp.MustCompile(`(?i)^[a-f0-9]{8,}$`)
)

type signatureInfo struct {
	Signer    string
	Publisher string
	Status    string
	Reason    string
}

type processIntelligence struct {
	row             map[string]any
	rawPath         string
	limited         bool
	suspicious      bool
	shouldHash      bool
	stringCandidate bool
	evidence        *contract.Evidence
	finding         *contract.Finding
}

type networkAccumulator struct {
	tcp       int
	udp       int
	remote    int
	states    map[string]int
	remoteSet map[string]bool
	samples   []string
}

func collectNetworkSummaries(ctx context.Context) map[int32]map[string]any {
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	connections, err := gopsnet.ConnectionsWithContext(timeoutCtx, "inet")
	if err != nil {
		return map[int32]map[string]any{}
	}

	accumulators := map[int32]*networkAccumulator{}
	for _, connection := range connections {
		if connection.Pid <= 0 {
			continue
		}
		acc := accumulators[connection.Pid]
		if acc == nil {
			acc = &networkAccumulator{
				states:    map[string]int{},
				remoteSet: map[string]bool{},
			}
			accumulators[connection.Pid] = acc
		}
		switch connection.Type {
		case 1:
			acc.tcp++
		case 2:
			acc.udp++
		}
		status := strings.TrimSpace(connection.Status)
		if status != "" {
			acc.states[status]++
		}
		if connection.Raddr.IP != "" {
			remote := fmt.Sprintf("%s:%d", connection.Raddr.IP, connection.Raddr.Port)
			if !acc.remoteSet[remote] {
				acc.remoteSet[remote] = true
				acc.remote++
				if len(acc.samples) < maxNetworkSamplesPerProcess {
					acc.samples = append(acc.samples, remote)
				}
			}
		}
	}

	summaries := map[int32]map[string]any{}
	for pid, acc := range accumulators {
		states := make([]string, 0, len(acc.states))
		for state, count := range acc.states {
			states = append(states, fmt.Sprintf("%s:%d", state, count))
		}
		sort.Strings(states)
		summaries[pid] = map[string]any{
			"tcpCount":          acc.tcp,
			"udpCount":          acc.udp,
			"remoteCount":       acc.remote,
			"states":            states,
			"sampleRemoteHosts": acc.samples,
			"source":            "gopsutil_net",
		}
	}

	return summaries
}

func redactCommandLine(value string) string {
	value = strings.TrimSpace(privacy.MaskPath(value))
	if value == "" {
		return ""
	}
	value = scannerSecretValue.ReplaceAllString(value, "[REDACTED]")
	value = commandSecretAssignment.ReplaceAllString(value, `${1}[REDACTED]`)
	value = commandSecretSeparated.ReplaceAllString(value, `${1}[REDACTED]`)
	value = urlSecretQuery.ReplaceAllString(value, `${1}[REDACTED]`)
	return value
}

func processSessionID(pid int32) (uint32, bool) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("ProcessIdToSessionId")
	var sessionID uint32
	ret, _, _ := proc.Call(uintptr(uint32(pid)), uintptr(unsafe.Pointer(&sessionID)))
	return sessionID, ret != 0
}

func suspiciousPathFlags(name string, rawPath string, sig signatureInfo) []string {
	normalized := strings.ToLower(strings.ReplaceAll(rawPath, "/", `\`))
	base := strings.ToLower(filepath.Base(rawPath))
	if base == "" {
		base = strings.ToLower(name)
	}

	flags := []string{}
	if strings.Contains(normalized, `\appdata\local\temp\`) || strings.Contains(normalized, `\temp\`) {
		flags = append(flags, "temp_path")
	}
	if strings.Contains(normalized, `\appdata\roaming\`) {
		flags = append(flags, "appdata_path")
	}
	if strings.Contains(normalized, `\appdata\local\`) {
		flags = append(flags, "localappdata_path")
	}
	if strings.Contains(normalized, `\downloads\`) {
		flags = append(flags, "downloads_path")
	}
	if strings.Contains(normalized, `\discord`) || strings.Contains(normalized, `\telegram desktop`) || strings.Contains(normalized, `\tdata\`) {
		flags = append(flags, "discord_or_telegram_path")
	}
	if looksWindowsLike(base) && !strings.Contains(normalized, `\windows\`) {
		flags = append(flags, "windows_like_name_outside_windows")
	}
	if looksRandomFilename(strings.TrimSuffix(base, filepath.Ext(base))) {
		flags = append(flags, "random_like_filename")
	}
	if sig.Status == "unsigned" && isUserWritablePath(normalized) {
		flags = append(flags, "unsigned_user_writable_path")
	}

	return uniqueStringsSorted(flags)
}

func isUserWritablePath(normalizedPath string) bool {
	return strings.Contains(normalizedPath, `\users\`) ||
		strings.Contains(normalizedPath, `\appdata\`) ||
		strings.Contains(normalizedPath, `\programdata\`) ||
		strings.Contains(normalizedPath, `\temp\`) ||
		strings.Contains(normalizedPath, `\downloads\`)
}

func looksWindowsLike(base string) bool {
	switch strings.ToLower(base) {
	case "svchost.exe", "conhost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "spoolsv.exe", "taskhostw.exe", "runtimebroker.exe", "dllhost.exe", "rundll32.exe", "regsvr32.exe", "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe":
		return true
	default:
		return false
	}
}

func looksRandomFilename(name string) bool {
	name = strings.TrimSpace(name)
	if len(name) < 8 {
		return false
	}
	if randomHexName.MatchString(name) {
		return true
	}

	letters := 0
	digits := 0
	vowels := 0
	for _, char := range name {
		switch {
		case unicode.IsDigit(char):
			digits++
		case unicode.IsLetter(char):
			letters++
			if strings.ContainsRune("aeiouAEIOU", char) {
				vowels++
			}
		}
	}
	return letters >= 6 && digits >= 2 && vowels == 0
}

func shouldCheckSignature(rawPath string, preFlags []string, match RuleMatch) bool {
	if strings.TrimSpace(rawPath) == "" {
		return false
	}
	normalized := strings.ToLower(strings.ReplaceAll(rawPath, "/", `\`))
	return len(preFlags) > 0 || match.Matched || isUserWritablePath(normalized)
}

func collectSignatureInfo(ctx context.Context, rawPath string) signatureInfo {
	if strings.TrimSpace(rawPath) == "" {
		return signatureInfo{Status: "unknown", Reason: "path_unavailable"}
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	escaped := strings.ReplaceAll(rawPath, `'`, `''`)
	command := "$ErrorActionPreference='Stop'; " +
		"$sig=Get-AuthenticodeSignature -LiteralPath '" + escaped + "'; " +
		"$publisher=''; $signer=''; " +
		"if ($sig.SignerCertificate) { $publisher=$sig.SignerCertificate.GetNameInfo('SimpleName',$false); $signer=$sig.SignerCertificate.Subject }; " +
		"[PSCustomObject]@{Status=[string]$sig.Status; Signer=$signer; Publisher=$publisher} | ConvertTo-Json -Compress"
	output, err := hiddenCommand(timeoutCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command).Output()
	if err != nil {
		return signatureInfo{Status: "unknown", Reason: "signature_unavailable"}
	}

	var parsed struct {
		Status    string
		Signer    string
		Publisher string
	}
	if err := json.Unmarshal(output, &parsed); err != nil {
		return signatureInfo{Status: "unknown", Reason: "signature_parse_failed"}
	}

	status := "unknown"
	switch strings.ToLower(strings.TrimSpace(parsed.Status)) {
	case "valid":
		status = "signed"
	case "notsigned":
		status = "unsigned"
	case "":
		status = "unknown"
	default:
		status = strings.ToLower(strings.TrimSpace(parsed.Status))
	}

	return signatureInfo{
		Signer:    privacy.RedactString(parsed.Signer),
		Publisher: privacy.RedactString(parsed.Publisher),
		Status:    status,
	}
}

func classifyProcessStatus(limited bool, flags []string, match RuleMatch) string {
	if limited {
		return "limited"
	}
	if containsString(flags, "unsigned_user_writable_path") || containsString(flags, "windows_like_name_outside_windows") {
		return "suspicious"
	}
	if match.Matched && strings.EqualFold(match.Status, "suspicious") {
		return "suspicious"
	}
	if len(flags) > 0 || match.Matched {
		return "review"
	}
	return "running"
}

func confidenceForProcess(limitedReasons []string, flags []string, status string, match RuleMatch) int {
	confidence := 85 - len(limitedReasons)*8
	if match.Confidence > confidence {
		confidence = match.Confidence
	}
	if status == "suspicious" {
		confidence += 5
	}
	if len(flags) >= 2 {
		confidence += 5
	}
	if confidence < 25 {
		return 25
	}
	if confidence > 95 {
		return 95
	}
	return confidence
}

func buildSuspiciousProcessEvidence(row map[string]any, name string, pid int32, flags []string, severity string, confidence int) (contract.Evidence, contract.Finding) {
	evidenceID := fmt.Sprintf("process-%d", pid)
	evidence := contract.Evidence{
		ClientEvidenceID: evidenceID,
		Type:             "process",
		Title:            "Process intelligence: " + firstNonEmptyString(name, "Unknown"),
		Data:             privacy.RedactMap(row),
	}
	finding := contract.Finding{
		Category:     "PROCESS",
		Severity:     severity,
		Title:        "Suspicious process: " + firstNonEmptyString(name, "Unknown"),
		Message:      "A process matched suspicious path, signature, or utility heuristics and should be reviewed.",
		EvidenceRef:  evidenceID,
		Confidence:   confidence,
		SourceModule: "process_timeline",
		Metadata: privacy.RedactMap(map[string]any{
			"processName":     name,
			"pid":             pid,
			"path":            row["path"],
			"status":          row["status"],
			"suspiciousFlags": flags,
			"signatureStatus": row["signatureStatus"],
			"hashPrefix":      shortHashString(row["executableSha256"]),
		}),
	}
	return evidence, finding
}

func severityForProcess(status string, match RuleMatch) string {
	if match.Matched && strings.TrimSpace(match.Severity) != "" {
		return match.Severity
	}
	if status == "suspicious" {
		return "WARNING"
	}
	return "INFO"
}

func uniqueStringsSorted(values []string) []string {
	seen := map[string]bool{}
	clean := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		clean = append(clean, value)
	}
	sort.Strings(clean)
	return clean
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func shortHashString(value any) string {
	text, _ := value.(string)
	if len(text) <= 12 {
		return text
	}
	return text[:12]
}
