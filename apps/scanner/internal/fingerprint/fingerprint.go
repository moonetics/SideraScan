package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

const Version = "siderascan-fp-v1"

type Signal struct {
	Name  string
	Value string
}

type Result struct {
	Fingerprint contract.DeviceFingerprint
	SignalsUsed []string
}

func Build(signals []Signal) Result {
	normalized := normalizeSignals(signals)
	pairs := make([]string, 0, len(normalized))
	names := make([]string, 0, len(normalized))
	hasMachineGuid := false

	for _, signal := range normalized {
		if signal.Name == "machine_guid" {
			hasMachineGuid = true
		}
		names = append(names, signal.Name)
		pairs = append(pairs, signal.Name+"="+hashString(signal.Value))
	}

	sort.Strings(names)
	sort.Strings(pairs)
	finalHash := hashString("siderascan/device-fingerprint/" + Version + "\n" + strings.Join(pairs, "\n"))

	return Result{
		Fingerprint: contract.DeviceFingerprint{
			Hash:       finalHash,
			Version:    Version,
			Confidence: confidence(len(normalized), hasMachineGuid),
		},
		SignalsUsed: names,
	}
}

func normalizeSignals(signals []Signal) []Signal {
	seen := map[string]Signal{}
	for _, signal := range signals {
		name := normalize(signal.Name)
		value := strings.TrimSpace(signal.Value)
		if name == "" || value == "" {
			continue
		}
		seen[name] = Signal{Name: name, Value: value}
	}

	normalized := make([]Signal, 0, len(seen))
	for _, signal := range seen {
		normalized = append(normalized, signal)
	}
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].Name < normalized[j].Name
	})

	return normalized
}

func confidence(signalCount int, hasMachineGuid bool) string {
	if hasMachineGuid && signalCount >= 4 {
		return "HIGH"
	}
	if signalCount >= 2 {
		return "MEDIUM"
	}
	return "LOW"
}

func normalize(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "_")
	value = strings.ReplaceAll(value, "-", "_")
	return value
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
