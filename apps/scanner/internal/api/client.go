package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

const defaultTimeout = 15 * time.Second

const (
	NormalizeNetworkUnavailable   = "NETWORK_UNAVAILABLE"
	NormalizeRequestTimeout       = "REQUEST_TIMEOUT"
	NormalizeServerUnavailable    = "SERVER_UNAVAILABLE"
	NormalizeRateLimited          = "RATE_LIMITED"
	NormalizeUploadTokenExpired   = "UPLOAD_TOKEN_EXPIRED"
	NormalizeUploadAuthFailed     = "UPLOAD_AUTH_FAILED"
	NormalizeValidationFailed     = "VALIDATION_FAILED"
	NormalizeConfigUnavailable    = "CONFIG_UNAVAILABLE"
	NormalizePayloadPrepareFailed = "PAYLOAD_PREPARE_FAILED"
	NormalizeUploadFailed         = "UPLOAD_FAILED"
	NormalizeCompleteFailed       = "COMPLETE_FAILED"
	NormalizeRequestBodyTooLarge  = "REQUEST_BODY_TOO_LARGE"
)

type RetryPolicy struct {
	MaxAttempts int
	Timeout     time.Duration
	Backoff     []time.Duration
}

type OperationTelemetry struct {
	Attempts   int
	DurationMs int64
	LastCode   string
}

type Client struct {
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
	sleep      func(context.Context, time.Duration) error
}

type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("api error %d: %s", e.StatusCode, e.Code)
	}
	if e.Message != "" {
		return fmt.Sprintf("api error %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("api error %d", e.StatusCode)
}

func New(baseURL string, logger *slog.Logger) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{},
		logger:     logger,
		sleep:      sleepContext,
	}
}

func (c *Client) ValidateKey(ctx context.Context, req contract.ValidateKeyRequest) (contract.ValidateKeyResponse, error) {
	var out contract.ValidateKeyResponse
	_, err := c.postJSONWithPolicy(ctx, "/scanner/validate-key", req, &out, RetryPolicy{
		MaxAttempts: 2,
		Timeout:     15 * time.Second,
		Backoff:     []time.Duration{500 * time.Millisecond},
	})
	return out, err
}

func (c *Client) GetScannerConfig(ctx context.Context, req contract.ScannerConfigRequest) (contract.ScannerConfigResponse, error) {
	var out contract.ScannerConfigResponse
	_, err := c.postJSONWithPolicy(ctx, "/scanner/config", req, &out, RetryPolicy{
		MaxAttempts: 3,
		Timeout:     15 * time.Second,
		Backoff:     []time.Duration{500 * time.Millisecond, 1500 * time.Millisecond},
	})
	return out, err
}

func (c *Client) UploadResults(ctx context.Context, scanSessionID string, req contract.UploadResultsRequest) (contract.UploadResultsResponse, error) {
	out, _, err := c.UploadResultsWithTelemetry(ctx, scanSessionID, req)
	return out, err
}

func (c *Client) UploadResultsWithTelemetry(ctx context.Context, scanSessionID string, req contract.UploadResultsRequest) (contract.UploadResultsResponse, OperationTelemetry, error) {
	var out contract.UploadResultsResponse
	telemetry, err := c.postJSONWithPolicy(ctx, "/scanner/sessions/"+scanSessionID+"/results", req, &out, RetryPolicy{
		MaxAttempts: 3,
		Timeout:     30 * time.Second,
		Backoff:     []time.Duration{500 * time.Millisecond, 1500 * time.Millisecond},
	})
	return out, telemetry, err
}

func (c *Client) UploadCoreResultsWithTelemetry(ctx context.Context, scanSessionID string, req contract.UploadResultsRequest) (contract.UploadResultsResponse, OperationTelemetry, error) {
	var out contract.UploadResultsResponse
	telemetry, err := c.postJSONWithPolicy(ctx, "/scanner/sessions/"+scanSessionID+"/results/core", req, &out, RetryPolicy{
		MaxAttempts: 3,
		Timeout:     30 * time.Second,
		Backoff:     []time.Duration{500 * time.Millisecond, 1500 * time.Millisecond},
	})
	return out, telemetry, err
}

func (c *Client) UploadResultSectionWithTelemetry(ctx context.Context, scanSessionID string, req contract.UploadResultSectionRequest) (contract.UploadResultSectionResponse, OperationTelemetry, error) {
	var out contract.UploadResultSectionResponse
	telemetry, err := c.postJSONWithPolicy(ctx, "/scanner/sessions/"+scanSessionID+"/results/section", req, &out, RetryPolicy{
		MaxAttempts: 3,
		Timeout:     30 * time.Second,
		Backoff:     []time.Duration{500 * time.Millisecond, 1500 * time.Millisecond},
	})
	return out, telemetry, err
}

func (c *Client) CompleteSession(ctx context.Context, scanSessionID string, req contract.CompleteSessionRequest) (contract.CompleteSessionResponse, error) {
	out, _, err := c.CompleteSessionWithTelemetry(ctx, scanSessionID, req)
	return out, err
}

func (c *Client) CompleteSessionWithTelemetry(ctx context.Context, scanSessionID string, req contract.CompleteSessionRequest) (contract.CompleteSessionResponse, OperationTelemetry, error) {
	var out contract.CompleteSessionResponse
	telemetry, err := c.postJSONWithPolicy(ctx, "/scanner/sessions/"+scanSessionID+"/complete", req, &out, RetryPolicy{
		MaxAttempts: 3,
		Timeout:     20 * time.Second,
		Backoff:     []time.Duration{500 * time.Millisecond, 1500 * time.Millisecond},
	})
	return out, telemetry, err
}

func (c *Client) postJSON(ctx context.Context, path string, input any, output any) error {
	_, err := c.postJSONWithPolicy(ctx, path, input, output, RetryPolicy{
		MaxAttempts: 1,
		Timeout:     defaultTimeout,
	})
	return err
}

func (c *Client) postJSONWithPolicy(ctx context.Context, path string, input any, output any, policy RetryPolicy) (OperationTelemetry, error) {
	policy = normalizePolicy(policy)
	started := time.Now()
	telemetry := OperationTelemetry{}
	var lastErr error

	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		telemetry.Attempts = attempt
		attemptCtx, cancel := context.WithTimeout(ctx, policy.Timeout)
		err := c.postJSONOnce(attemptCtx, path, input, output)
		cancel()
		telemetry.DurationMs = time.Since(started).Milliseconds()
		telemetry.LastCode = NormalizeErrorCode(err)
		if err == nil {
			return telemetry, nil
		}

		lastErr = err
		if !ShouldRetry(err) || attempt >= policy.MaxAttempts {
			break
		}

		delay := backoffDelay(policy, attempt)
		if c.logger != nil {
			c.logger.Warn(
				"scanner api request retrying",
				"path", path,
				"attempt", attempt,
				"nextAttempt", attempt+1,
				"errorCode", telemetry.LastCode,
				"delayMs", delay.Milliseconds(),
			)
		}
		if err := c.sleep(ctx, delay); err != nil {
			lastErr = APIError{StatusCode: 0, Code: "TIMEOUT", Message: "Retry interrupted"}
			break
		}
	}

	telemetry.DurationMs = time.Since(started).Milliseconds()
	telemetry.LastCode = NormalizeErrorCode(lastErr)
	return telemetry, lastErr
}

func (c *Client) postJSONOnce(ctx context.Context, path string, input any, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}

	started := time.Now()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("accept", "application/json")

	response, err := c.httpClient.Do(request)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return APIError{StatusCode: 0, Code: "TIMEOUT", Message: "Request timed out"}
		}
		return APIError{StatusCode: 0, Code: "NETWORK_ERROR", Message: "Unable to reach server"}
	}
	defer response.Body.Close()

	durationMs := time.Since(started).Milliseconds()
	if c.logger != nil {
		c.logger.Info(
			"scanner api request completed",
			"path", path,
			"statusCode", response.StatusCode,
			"durationMs", durationMs,
		)
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return parseAPIError(response)
	}

	if output == nil {
		return nil
	}

	if err := json.NewDecoder(response.Body).Decode(output); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

func normalizePolicy(policy RetryPolicy) RetryPolicy {
	if policy.MaxAttempts < 1 {
		policy.MaxAttempts = 1
	}
	if policy.Timeout <= 0 {
		policy.Timeout = defaultTimeout
	}
	return policy
}

func backoffDelay(policy RetryPolicy, attempt int) time.Duration {
	index := attempt - 1
	if index >= 0 && index < len(policy.Backoff) {
		return policy.Backoff[index]
	}
	return 3 * time.Second
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func ShouldRetry(err error) bool {
	if err == nil {
		return false
	}
	apiErr, ok := err.(APIError)
	if !ok {
		return false
	}
	switch apiErr.Code {
	case "NETWORK_ERROR", "TIMEOUT":
		return true
	case "KEY_REVOKED", "KEY_EXPIRED", "VERSION_NOT_ALLOWED", "ACCOUNT_DISABLED", "INVALID_KEY":
		return false
	}
	switch apiErr.StatusCode {
	case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict:
		return false
	default:
		return apiErr.StatusCode >= 500
	}
}

func NormalizeErrorCode(err error) string {
	if err == nil {
		return ""
	}
	apiErr, ok := err.(APIError)
	if !ok {
		return NormalizeUploadFailed
	}
	switch apiErr.Code {
	case "NETWORK_ERROR":
		return NormalizeNetworkUnavailable
	case "TIMEOUT":
		return NormalizeRequestTimeout
	case "KEY_EXPIRED":
		return NormalizeUploadTokenExpired
	case "INVALID_UPLOAD_TOKEN", "INVALID_NONCE", "UPLOAD_TOKEN_EXPIRED":
		return NormalizeUploadAuthFailed
	case "INVALID_KEY", "KEY_REVOKED", "VERSION_NOT_ALLOWED", "ACCOUNT_DISABLED":
		return NormalizeValidationFailed
	}
	switch apiErr.StatusCode {
	case http.StatusTooManyRequests:
		return NormalizeRateLimited
	case http.StatusRequestEntityTooLarge:
		return NormalizeRequestBodyTooLarge
	case http.StatusUnauthorized, http.StatusForbidden:
		return NormalizeUploadAuthFailed
	case http.StatusRequestTimeout:
		return NormalizeRequestTimeout
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return NormalizeServerUnavailable
	default:
		if apiErr.StatusCode >= 500 {
			return NormalizeServerUnavailable
		}
	}
	return NormalizeUploadFailed
}

func parseAPIError(response *http.Response) error {
	limited := io.LimitReader(response.Body, 2048)
	bytes, _ := io.ReadAll(limited)
	parsed := struct {
		ErrorCode string `json:"errorCode"`
		Message   any    `json:"message"`
		Error     string `json:"error"`
	}{}
	_ = json.Unmarshal(bytes, &parsed)

	message := parsed.Error
	switch value := parsed.Message.(type) {
	case string:
		message = value
	case []any:
		if len(value) > 0 {
			message = fmt.Sprint(value[0])
		}
	}
	if message == "" {
		message = strings.TrimSpace(string(bytes))
	}

	return APIError{
		StatusCode: response.StatusCode,
		Code:       parsed.ErrorCode,
		Message:    message,
	}
}
