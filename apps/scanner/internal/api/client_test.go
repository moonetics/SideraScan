package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

func TestClientSendsCamelCaseValidateRequest(t *testing.T) {
	requestSeen := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/scanner/validate-key" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		requestSeen <- body
		_, _ = w.Write([]byte(`{"valid":true,"accountId":"acc_1","accountName":"Account","scanSessionId":"scan_1","uploadToken":"up","nonce":"nn","enabledModules":["overview"]}`))
	}))
	defer server.Close()

	client := New(server.URL, nil)
	response, err := client.ValidateKey(context.Background(), contract.ValidateKeyRequest{
		ScannerKey:     "sds_live_secret",
		ScannerVersion: "0.1.0",
		Platform:       "windows",
		Arch:           "amd64",
	})
	if err != nil {
		t.Fatalf("validate key failed: %v", err)
	}
	if !response.Valid || response.ScanSessionID != "scan_1" {
		t.Fatalf("unexpected response: %+v", response)
	}

	body := <-requestSeen
	if _, ok := body["scannerKey"]; !ok {
		t.Fatal("expected scannerKey camelCase field")
	}
	if _, ok := body["scanner_key"]; ok {
		t.Fatal("did not expect scanner_key snake_case field")
	}
	if body["scannerVersion"] != "0.1.0" {
		t.Fatalf("expected scannerVersion, got %#v", body["scannerVersion"])
	}
}

func TestClientHappyPathAgainstMockedScannerAPI(t *testing.T) {
	paths := make([]string, 0, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/scanner/validate-key":
			_, _ = w.Write([]byte(`{"valid":true,"accountId":"acc_1","accountName":"Account","scanSessionId":"scan_1","uploadToken":"upload","nonce":"nonce","enabledModules":["overview"]}`))
		case "/scanner/config":
			_, _ = w.Write([]byte(`{"status":"ok","accountId":"acc_1","accountName":"Account","scannerVersion":"0.1.0","rules":[]}`))
		case "/scanner/sessions/scan_1/results":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode upload: %v", err)
			}
			if _, ok := body["accountId"]; ok {
				t.Fatal("upload body must not include accountId")
			}
			if _, ok := body["scannerKey"]; ok {
				t.Fatal("upload body must not include scannerKey")
			}
			_, _ = w.Write([]byte(`{"status":"ok","scanSessionId":"scan_1","storedFindings":0}`))
		case "/scanner/sessions/scan_1/complete":
			_, _ = w.Write([]byte(`{"status":"ok","scanSessionId":"scan_1","scanStatus":"COMPLETED"}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := New(server.URL, nil)
	validate, err := client.ValidateKey(context.Background(), contract.ValidateKeyRequest{
		ScannerKey:     "sds_live_secret",
		ScannerVersion: "0.1.0",
		Platform:       "windows",
		Arch:           "amd64",
	})
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if _, err := client.GetScannerConfig(context.Background(), contract.ScannerConfigRequest{
		ScannerKey:     "sds_live_secret",
		ScannerVersion: "0.1.0",
	}); err != nil {
		t.Fatalf("config failed: %v", err)
	}
	if _, err := client.UploadResults(context.Background(), validate.ScanSessionID, contract.UploadResultsRequest{
		UploadToken: validate.UploadToken,
		Nonce:       validate.Nonce,
	}); err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	if _, err := client.CompleteSession(context.Background(), validate.ScanSessionID, contract.CompleteSessionRequest{
		UploadToken: validate.UploadToken,
		Nonce:       validate.Nonce,
		Status:      "COMPLETED",
	}); err != nil {
		t.Fatalf("complete failed: %v", err)
	}

	want := []string{
		"/scanner/validate-key",
		"/scanner/config",
		"/scanner/sessions/scan_1/results",
		"/scanner/sessions/scan_1/complete",
	}
	if len(paths) != len(want) {
		t.Fatalf("unexpected request count: got %v want %v", paths, want)
	}
	for index := range want {
		if paths[index] != want[index] {
			t.Fatalf("unexpected path order: got %v want %v", paths, want)
		}
	}
}

func TestClientUploadsCoreAndSection(t *testing.T) {
	paths := make([]string, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if _, ok := body["accountId"]; ok {
			t.Fatal("chunked upload body must not include accountId")
		}
		switch r.URL.Path {
		case "/scanner/sessions/scan_1/results/core":
			_, _ = w.Write([]byte(`{"status":"ok","scanSessionId":"scan_1","storedFindings":1}`))
		case "/scanner/sessions/scan_1/results/section":
			if body["section"] != "processTimeline" {
				t.Fatalf("unexpected section %#v", body["section"])
			}
			_, _ = w.Write([]byte(`{"status":"ok","scanSessionId":"scan_1","section":"processTimeline","uploadedItems":1}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := New(server.URL, nil)
	if _, _, err := client.UploadCoreResultsWithTelemetry(context.Background(), "scan_1", contract.UploadResultsRequest{
		UploadToken: "upload",
		Nonce:       "nonce",
		Findings:    []contract.Finding{{Title: "finding", Message: "message"}},
	}); err != nil {
		t.Fatalf("core upload failed: %v", err)
	}
	if _, _, err := client.UploadResultSectionWithTelemetry(context.Background(), "scan_1", contract.UploadResultSectionRequest{
		UploadToken: "upload",
		Nonce:       "nonce",
		Section:     "processTimeline",
		Items:       []any{map[string]any{"processName": "RobloxPlayerBeta.exe"}},
		TotalItems:  1,
		ChunkCount:  1,
		Status:      "uploaded",
	}); err != nil {
		t.Fatalf("section upload failed: %v", err)
	}
	if len(paths) != 2 || paths[0] != "/scanner/sessions/scan_1/results/core" || paths[1] != "/scanner/sessions/scan_1/results/section" {
		t.Fatalf("unexpected paths: %v", paths)
	}
}

func TestClientRetriesRetryableUploadFailure(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			http.Error(w, `{"message":"temporary unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","scanSessionId":"scan_1","storedFindings":1}`))
	}))
	defer server.Close()

	client := New(server.URL, nil)
	client.sleep = func(ctx context.Context, duration time.Duration) error {
		return nil
	}
	response, telemetry, err := client.UploadResultsWithTelemetry(context.Background(), "scan_1", contract.UploadResultsRequest{
		UploadToken: "upload",
		Nonce:       "nonce",
	})
	if err != nil {
		t.Fatalf("expected retry success, got %v", err)
	}
	if response.StoredFindings != 1 {
		t.Fatalf("unexpected response: %+v", response)
	}
	if attempts != 3 || telemetry.Attempts != 3 {
		t.Fatalf("expected 3 attempts, server=%d telemetry=%d", attempts, telemetry.Attempts)
	}
}

func TestClientDoesNotRetryNonRetryableValidationFailure(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errorCode":"KEY_REVOKED","message":"revoked"}`))
	}))
	defer server.Close()

	client := New(server.URL, nil)
	client.sleep = func(ctx context.Context, duration time.Duration) error {
		t.Fatal("sleep should not be called for non-retryable error")
		return nil
	}
	_, err := client.ValidateKey(context.Background(), contract.ValidateKeyRequest{
		ScannerKey:     "revoked",
		ScannerVersion: "0.1.0",
		Platform:       "windows",
		Arch:           "amd64",
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
	if attempts != 1 {
		t.Fatalf("expected 1 attempt, got %d", attempts)
	}
	if got := NormalizeErrorCode(err); got != NormalizeValidationFailed {
		t.Fatalf("expected validation normalized error, got %q", got)
	}
}

func TestClientDoesNotRetryVersionBlocked(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errorCode":"VERSION_NOT_ALLOWED","message":"blocked"}`))
	}))
	defer server.Close()

	client := New(server.URL, nil)
	client.sleep = func(ctx context.Context, duration time.Duration) error {
		t.Fatal("sleep should not be called for version blocked")
		return nil
	}
	_, err := client.ValidateKey(context.Background(), contract.ValidateKeyRequest{
		ScannerKey:     "blocked",
		ScannerVersion: "0.1.0",
		Platform:       "windows",
		Arch:           "amd64",
	})
	if err == nil {
		t.Fatal("expected version blocked error")
	}
	apiErr, ok := err.(APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.Code != "VERSION_NOT_ALLOWED" {
		t.Fatalf("expected VERSION_NOT_ALLOWED code, got %q", apiErr.Code)
	}
	if attempts != 1 {
		t.Fatalf("expected one attempt, got %d", attempts)
	}
}

func TestClientNormalizesNetworkFailure(t *testing.T) {
	client := New("http://127.0.0.1:1", nil)
	client.sleep = func(ctx context.Context, duration time.Duration) error {
		return nil
	}
	_, telemetry, err := client.UploadResultsWithTelemetry(context.Background(), "scan_1", contract.UploadResultsRequest{
		UploadToken: "upload",
		Nonce:       "nonce",
	})
	if err == nil {
		t.Fatal("expected network error")
	}
	if telemetry.Attempts != 3 {
		t.Fatalf("expected 3 upload attempts, got %d", telemetry.Attempts)
	}
	if got := NormalizeErrorCode(err); got != NormalizeNetworkUnavailable {
		t.Fatalf("expected network unavailable normalized error, got %q", got)
	}
}

func TestClientParsesScannerConfigRules(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","accountId":"acc_1","accountName":"Account","scannerVersion":"0.1.0","rules":[{"id":"rule_1","scope":"GLOBAL","name":"Rule","type":"PROCESS_NAME","category":"CUSTOM_DETECTION","severity":"WARNING","ruleConfig":{"processNames":["tool.exe"]},"updatedAt":"2026-08-13T00:00:00Z"}]}`))
	}))
	defer server.Close()

	client := New(server.URL, nil)
	response, err := client.GetScannerConfig(context.Background(), contract.ScannerConfigRequest{
		ScannerKey:     "sds_live_secret",
		ScannerVersion: "0.1.0",
	})
	if err != nil {
		t.Fatalf("config failed: %v", err)
	}
	if len(response.Rules) != 1 {
		t.Fatalf("expected one rule, got %d", len(response.Rules))
	}
	if response.Rules[0].RuleConfig["processNames"] == nil {
		t.Fatalf("expected rule config to parse, got %#v", response.Rules[0].RuleConfig)
	}
}

func TestClientCompleteSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/scanner/sessions/scan_1/complete" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body["status"] != "COMPLETED" {
			t.Fatalf("expected completed status, got %#v", body["status"])
		}
		telemetry, ok := body["telemetry"].(map[string]any)
		if !ok {
			t.Fatal("expected complete telemetry")
		}
		if telemetry["uploadAttemptCount"] != float64(2) {
			t.Fatalf("expected uploadAttemptCount telemetry, got %#v", telemetry)
		}
		_, _ = w.Write([]byte(`{"status":"ok","scanSessionId":"scan_1","scanStatus":"COMPLETED"}`))
	}))
	defer server.Close()

	client := New(server.URL, nil)
	response, err := client.CompleteSession(context.Background(), "scan_1", contract.CompleteSessionRequest{
		UploadToken: "upload",
		Nonce:       "nonce",
		Status:      "COMPLETED",
		Telemetry: &contract.CompleteTelemetry{
			UploadAttemptCount: 2,
			ScannerVersion:     "0.1.0",
		},
	})
	if err != nil {
		t.Fatalf("complete failed: %v", err)
	}
	if response.ScanStatus != "COMPLETED" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestNormalizeRequestBodyTooLarge(t *testing.T) {
	err := APIError{StatusCode: http.StatusRequestEntityTooLarge, Message: "request body is too large"}
	if got := NormalizeErrorCode(err); got != NormalizeRequestBodyTooLarge {
		t.Fatalf("expected body-too-large normalization, got %q", got)
	}
	if ShouldRetry(err) {
		t.Fatal("413 should not be retried by generic retry policy")
	}
}

func TestClientUploadResultsUsesSessionEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/scanner/sessions/scan_1/results" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body["uploadToken"] != "upload" || body["nonce"] != "nonce" {
			t.Fatalf("expected upload token and nonce, got %#v", body)
		}
		if _, ok := body["scannerKey"]; ok {
			t.Fatal("upload body must not contain scannerKey")
		}
		if _, ok := body["accountId"]; ok {
			t.Fatal("upload body must not contain accountId")
		}
		_, _ = w.Write([]byte(`{"status":"ok","scanSessionId":"scan_1","storedFindings":1}`))
	}))
	defer server.Close()

	client := New(server.URL, nil)
	response, err := client.UploadResults(context.Background(), "scan_1", contract.UploadResultsRequest{
		UploadToken: "upload",
		Nonce:       "nonce",
	})
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	if response.StoredFindings != 1 {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestClientReturnsAPIErrorForNonSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"Invalid scanner key"}`, http.StatusUnauthorized)
	}))
	defer server.Close()

	client := New(server.URL, nil)
	_, err := client.GetScannerConfig(context.Background(), contract.ScannerConfigRequest{
		ScannerKey:     "bad",
		ScannerVersion: "0.1.0",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", apiErr.StatusCode)
	}
}
