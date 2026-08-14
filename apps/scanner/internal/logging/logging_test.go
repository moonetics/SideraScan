package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestRedactAttrRedactsSensitiveKeys(t *testing.T) {
	tests := []string{
		"scannerKey",
		"uploadToken",
		"nonce",
		"password",
		"token",
	}

	for _, key := range tests {
		t.Run(key, func(t *testing.T) {
			attr := RedactAttr(slog.String(key, "secret-value"))
			if attr.Value.String() != redactedValue {
				t.Fatalf("expected redacted value for %s, got %q", key, attr.Value.String())
			}
		})
	}
}

func TestLoggerDoesNotWriteSecretValues(t *testing.T) {
	var buffer bytes.Buffer
	logger := New(&buffer, "dev")

	logger.Info("test", "scannerKey", "sds_live_secret", "safe", "visible")

	output := buffer.String()
	if strings.Contains(output, "sds_live_secret") {
		t.Fatalf("logger output leaked scanner key: %s", output)
	}
	if !strings.Contains(output, redactedValue) {
		t.Fatalf("logger output did not contain redaction marker: %s", output)
	}
	if !strings.Contains(output, "visible") {
		t.Fatalf("logger output should preserve safe values: %s", output)
	}
}
