package detections

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

func TestEvaluateProcessNameRules(t *testing.T) {
	result := Evaluate(context.Background(), Input{
		Rules: []contract.ScannerRule{
			rule("11111111-1111-1111-1111-111111111111", RuleProcessName, map[string]any{
				"processNames": []any{"RobloxPlayerBeta.exe"},
				"matchMode":    "exact",
			}),
			rule("22222222-2222-2222-2222-222222222222", RuleProcessName, map[string]any{
				"processNames": []any{"PlayerBeta"},
				"matchMode":    "contains",
			}),
			rule("33333333-3333-3333-3333-333333333333", RuleProcessName, map[string]any{
				"processNames": []any{`Roblox.*Beta\.exe`},
				"matchMode":    "regex",
			}),
		},
		Payload: contract.UploadResultsRequest{
			ProcessTimeline: []map[string]any{
				{"processName": "RobloxPlayerBeta.exe", "path": `C:\Users\***\RobloxPlayerBeta.exe`},
			},
		},
	})

	if len(result.Findings) != 3 {
		t.Fatalf("expected three process rule findings, got %d", len(result.Findings))
	}
	for _, finding := range result.Findings {
		if finding.RuleID == "" {
			t.Fatal("expected ruleId on process finding")
		}
	}
}

func TestEvaluateInvalidRegexSkipsRule(t *testing.T) {
	result := Evaluate(context.Background(), Input{
		Rules: []contract.ScannerRule{
			rule("11111111-1111-1111-1111-111111111111", RuleProcessName, map[string]any{
				"processNames": []any{"["},
				"matchMode":    "regex",
			}),
		},
		Payload: contract.UploadResultsRequest{
			ProcessTimeline: []map[string]any{{"processName": "RobloxPlayerBeta.exe"}},
		},
	})

	if len(result.Findings) != 0 {
		t.Fatalf("expected invalid regex to produce no findings, got %d", len(result.Findings))
	}
}

func TestEvaluatePathPatternRules(t *testing.T) {
	result := Evaluate(context.Background(), Input{
		Rules: []contract.ScannerRule{
			rule("11111111-1111-1111-1111-111111111111", RulePathPattern, map[string]any{
				"patterns":  []any{"Bloxstrap"},
				"matchMode": "contains",
			}),
			rule("22222222-2222-2222-2222-222222222222", RulePathPattern, map[string]any{
				"patterns":  []any{"*/bloxstrap/*"},
				"matchMode": "glob",
			}),
		},
		Payload: contract.UploadResultsRequest{
			ClientModAssets: []contract.ClientModAsset{
				{Name: "Bloxstrap Modifications", Path: `C:\Users\***\AppData\Local\Bloxstrap\Modifications`},
			},
		},
	})

	if len(result.Findings) != 2 {
		t.Fatalf("expected two path findings, got %d", len(result.Findings))
	}
}

func TestEvaluateFileHashRule(t *testing.T) {
	result := Evaluate(context.Background(), Input{
		Rules: []contract.ScannerRule{
			rule("11111111-1111-1111-1111-111111111111", RuleFileHash, map[string]any{
				"hashes":    []any{"abcdef1234567890"},
				"algorithm": "sha256",
			}),
		},
		Payload: contract.UploadResultsRequest{
			LauncherProfiles: []contract.LauncherProfile{
				{ProfileName: "Bloxstrap", ExecutableHash: "abcdef1234567890"},
			},
		},
	})

	if len(result.Findings) != 1 {
		t.Fatalf("expected hash finding, got %d", len(result.Findings))
	}
	if result.Findings[0].RuleID == "" {
		t.Fatal("expected ruleId on hash finding")
	}
}

func TestEvaluateStringSignatureRuleScopedFile(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "ClientSettings.json")
	if err := os.WriteFile(filePath, []byte("prefix\x00unique_signature_value\x00suffix"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("unique_signature_value"))

	result := Evaluate(context.Background(), Input{
		Rules: []contract.ScannerRule{
			rule("11111111-1111-1111-1111-111111111111", RuleStringSignature, map[string]any{
				"strings": []any{
					map[string]any{
						"valueHash": hex.EncodeToString(sum[:]),
						"preview":   "unique_signature_value",
					},
				},
			}),
		},
		StringCandidateFiles: []string{filePath},
	})

	if len(result.Findings) != 1 {
		t.Fatalf("expected string signature finding, got %d partial=%v invalid=%d", len(result.Findings), result.PartialErrors, result.InvalidRuleCount)
	}
	if result.Findings[0].RuleID == "" {
		t.Fatal("expected ruleId on string finding")
	}
}

func TestEvaluateStringSignatureDoesNotReadUnscopedFile(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "ClientSettings.json")
	if err := os.WriteFile(filePath, []byte("unique_signature_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("unique_signature_value"))

	result := Evaluate(context.Background(), Input{
		Rules: []contract.ScannerRule{
			rule("11111111-1111-1111-1111-111111111111", RuleStringSignature, map[string]any{
				"strings": []any{
					map[string]any{"valueHash": hex.EncodeToString(sum[:]), "preview": "unique_signature_value"},
				},
			}),
		},
		StringCandidateFiles: nil,
	})

	if len(result.Findings) != 0 {
		t.Fatalf("expected no finding without scoped candidate file, got %d for %s", len(result.Findings), filePath)
	}
}

func TestEvaluateStringSignatureSkipsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "LargeClient.exe")
	file, err := os.Create(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(MaxStringScanFileBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	_ = file.Close()
	sum := sha256.Sum256([]byte("unique_signature_value"))

	result := Evaluate(context.Background(), Input{
		Rules: []contract.ScannerRule{
			rule("11111111-1111-1111-1111-111111111111", RuleStringSignature, map[string]any{
				"strings": []any{
					map[string]any{"valueHash": hex.EncodeToString(sum[:]), "preview": "unique_signature_value"},
				},
			}),
		},
		StringCandidateFiles: []string{filePath},
	})

	if len(result.Findings) != 0 {
		t.Fatalf("expected oversized file to be skipped, got %d findings", len(result.Findings))
	}
	if result.InvalidRuleCount == 0 && len(result.PartialErrors) == 0 {
		t.Fatal("expected oversized file to produce partial rule telemetry")
	}
}

func TestEvaluateFindingMetadataIsRedacted(t *testing.T) {
	result := Evaluate(context.Background(), Input{
		Rules: []contract.ScannerRule{
			rule("11111111-1111-1111-1111-111111111111", RulePathPattern, map[string]any{
				"patterns":  []any{"Roblox"},
				"matchMode": "contains",
			}),
		},
		Payload: contract.UploadResultsRequest{
			FileLogs: []contract.FileLog{
				{Action: "downloaded_file", Path: `C:\Users\Alice\Downloads\RobloxTool.exe`, Source: "downloads_metadata"},
			},
		},
	})

	if len(result.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(result.Findings))
	}
	bytes, err := json.Marshal(result.Findings[0])
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(bytes))
	for _, forbidden := range []string{"alice", "scannerkey", "uploadtoken", "nonce", "password", "cookie", "clipboard"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("finding contains forbidden text %q: %s", forbidden, text)
		}
	}
}

func TestExecutorIntelligenceNameOnlyIsInfo(t *testing.T) {
	result := Evaluate(context.Background(), Input{
		Rules: []contract.ScannerRule{
			executorRule("11111111-1111-1111-1111-111111111111", RuleProcessName, map[string]any{
				"processNames":  []any{"solara.exe"},
				"matchMode":     "exact",
				"executorName":  "Solara",
				"executorType":  "wexecutor",
				"managedBy":     ExecutorIntelligenceManagedBy,
				"reviewOnly":    true,
				"updateStatus":  true,
				"detected":      false,
				"feedUpdatedAt": "2026-08-14T00:00:00Z",
			}),
		},
		Payload: contract.UploadResultsRequest{
			ProcessTimeline: []map[string]any{
				{"processName": "solara.exe", "path": `C:\Program Files\Solara\solara.exe`, "status": "running"},
			},
		},
	})

	if len(result.Findings) != 1 {
		t.Fatalf("expected one executor finding, got %d", len(result.Findings))
	}
	finding := result.Findings[0]
	if finding.SourceModule != "executor_intelligence" {
		t.Fatalf("expected executor intelligence source module, got %s", finding.SourceModule)
	}
	if finding.Severity != "INFO" {
		t.Fatalf("expected name-only executor match to be INFO, got %s", finding.Severity)
	}
}

func TestExecutorIntelligenceMultiSignalCapsAtWarning(t *testing.T) {
	result := Evaluate(context.Background(), Input{
		Rules: []contract.ScannerRule{
			executorRule("11111111-1111-1111-1111-111111111111", RulePathPattern, map[string]any{
				"patterns":      []any{"solara"},
				"matchMode":     "contains",
				"executorName":  "Solara",
				"managedBy":     ExecutorIntelligenceManagedBy,
				"reviewOnly":    true,
				"updateStatus":  true,
				"detected":      true,
				"feedUpdatedAt": "2026-08-14T00:00:00Z",
			}),
		},
		Payload: contract.UploadResultsRequest{
			ProcessTimeline: []map[string]any{
				{
					"processName":     "solara.exe",
					"path":            `C:\Users\***\Downloads\solara.exe`,
					"signatureStatus": "unsigned",
					"suspiciousFlags": []any{"downloads_path", "unsigned_user_writable_path"},
				},
			},
		},
	})

	if len(result.Findings) != 1 {
		t.Fatalf("expected one executor finding, got %d", len(result.Findings))
	}
	finding := result.Findings[0]
	if finding.Severity != "WARNING" {
		t.Fatalf("expected multi-signal executor match to be WARNING, got %s", finding.Severity)
	}
	if strings.Contains(finding.Severity, "SEVERE") {
		t.Fatal("executor intelligence should never escalate to severe by itself")
	}
}

func rule(id string, ruleType string, config map[string]any) contract.ScannerRule {
	return contract.ScannerRule{
		ID:         id,
		Name:       "Test Rule",
		Type:       ruleType,
		Category:   DefaultCategory,
		Severity:   DefaultSeverity,
		RuleConfig: config,
	}
}

func executorRule(id string, ruleType string, config map[string]any) contract.ScannerRule {
	rule := rule(id, ruleType, config)
	rule.ManagedBy = ExecutorIntelligenceManagedBy
	rule.Severity = "SEVERE"
	return rule
}
