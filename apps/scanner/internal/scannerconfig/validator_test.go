package scannerconfig

import (
	"errors"
	"testing"
	"time"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

func TestValidateResponseAcceptsValidConfig(t *testing.T) {
	result, err := ValidateResponse(contract.ScannerSession{AccountID: "acc_1"}, contract.ScannerConfigResponse{
		Status:         "ok",
		AccountID:      "acc_1",
		ScannerVersion: "0.1.0",
		Rules: []contract.ScannerRule{
			rule("PROCESS_NAME", map[string]any{
				"processNames": []any{"RobloxPlayerBeta.exe"},
				"matchMode":    "exact",
			}),
		},
	}, "0.1.0")

	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	if result.Partial {
		t.Fatalf("expected full config, got warnings %v", result.Warnings)
	}
	if len(result.Config.Rules) != 1 {
		t.Fatalf("expected one rule, got %d", len(result.Config.Rules))
	}
	if result.Config.AdvancedForensics.MaxRowsPerModule != 250 {
		t.Fatalf("expected default forensic row cap, got %d", result.Config.AdvancedForensics.MaxRowsPerModule)
	}
	if result.Config.AdvancedForensics.MaxPayloadBytes != 24*1024*1024 || result.Config.AdvancedForensics.MaxTimelineRows != 350 {
		t.Fatalf("expected default payload/timeline caps, got %+v", result.Config.AdvancedForensics)
	}
}

func TestValidateResponseRejectsAccountMismatch(t *testing.T) {
	_, err := ValidateResponse(contract.ScannerSession{AccountID: "acc_1"}, contract.ScannerConfigResponse{
		Status:    "ok",
		AccountID: "acc_2",
	}, "0.1.0")

	if !errors.Is(err, ErrAccountMismatch) {
		t.Fatalf("expected account mismatch, got %v", err)
	}
}

func TestValidateResponseSkipsInvalidRules(t *testing.T) {
	result, err := ValidateResponse(contract.ScannerSession{AccountID: "acc_1"}, contract.ScannerConfigResponse{
		Status:         "ok",
		AccountID:      "acc_1",
		ScannerVersion: "0.1.0",
		Rules: []contract.ScannerRule{
			rule("PROCESS_NAME", map[string]any{"processNames": []any{"RobloxPlayerBeta.exe"}, "matchMode": "exact"}),
			rule("UNSUPPORTED", map[string]any{}),
			rule("FILE_HASH", map[string]any{"hashes": []any{"abc"}, "algorithm": "md5"}),
		},
	}, "0.1.0")

	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	if !result.Partial {
		t.Fatal("expected partial config")
	}
	if len(result.Config.Rules) != 1 {
		t.Fatalf("expected one valid rule after filtering, got %d", len(result.Config.Rules))
	}
}

func TestValidateResponseVersionMismatchFallsBackToNoRules(t *testing.T) {
	result, err := ValidateResponse(contract.ScannerSession{AccountID: "acc_1"}, contract.ScannerConfigResponse{
		Status:         "ok",
		AccountID:      "acc_1",
		ScannerVersion: "0.2.0",
		Rules:          []contract.ScannerRule{rule("PROCESS_NAME", map[string]any{"processNames": []any{"x.exe"}, "matchMode": "exact"})},
	}, "0.1.0")

	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	if !result.Partial || len(result.Config.Rules) != 0 {
		t.Fatalf("expected partial fallback with no rules, got partial=%v rules=%d", result.Partial, len(result.Config.Rules))
	}
}

func TestValidateResponsePreservesEnabledAdvancedForensics(t *testing.T) {
	result, err := ValidateResponse(contract.ScannerSession{AccountID: "acc_1"}, contract.ScannerConfigResponse{
		Status:         "ok",
		AccountID:      "acc_1",
		ScannerVersion: "0.1.0",
		AdvancedForensics: contract.AdvancedForensicsConfig{
			Enabled: true,
			Modules: contract.AdvancedForensicsModules{
				LoadedModules: true,
				EventLogs:     true,
			},
			MaxRowsPerModule:       250,
			MaxFileHashMB:          50,
			BrowserDownloadHistory: true,
		},
	}, "0.1.0")

	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	if !result.Config.AdvancedForensics.Enabled {
		t.Fatal("expected advanced forensics enabled")
	}
	if !result.Config.AdvancedForensics.Modules.LoadedModules || !result.Config.AdvancedForensics.Modules.EventLogs {
		t.Fatalf("expected enabled forensic modules, got %+v", result.Config.AdvancedForensics.Modules)
	}
	if result.Config.AdvancedForensics.MaxRowsPerModule != 250 || result.Config.AdvancedForensics.MaxFileHashMB != 50 {
		t.Fatalf("unexpected forensic caps: %+v", result.Config.AdvancedForensics)
	}
}

func rule(ruleType string, config map[string]any) contract.ScannerRule {
	return contract.ScannerRule{
		ID:         "11111111-1111-1111-1111-111111111111",
		Scope:      "GLOBAL",
		Name:       "Test Rule",
		Type:       ruleType,
		Category:   "CUSTOM_DETECTION",
		Severity:   "WARNING",
		RuleConfig: config,
		UpdatedAt:  time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC),
	}
}
