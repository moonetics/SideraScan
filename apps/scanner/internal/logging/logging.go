package logging

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

const redactedValue = "[REDACTED]"

type redactingHandler struct {
	next slog.Handler
}

func New(writer io.Writer, buildMode string) *slog.Logger {
	level := slog.LevelInfo
	if strings.EqualFold(buildMode, "dev") {
		level = slog.LevelDebug
	}

	handler := slog.NewJSONHandler(writer, &slog.HandlerOptions{
		Level: level,
	})

	return slog.New(redactingHandler{next: handler})
}

func (h redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h redactingHandler) Handle(ctx context.Context, record slog.Record) error {
	clean := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)
	record.Attrs(func(attr slog.Attr) bool {
		clean.AddAttrs(RedactAttr(attr))
		return true
	})

	return h.next.Handle(ctx, clean)
}

func (h redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clean := make([]slog.Attr, 0, len(attrs))
	for _, attr := range attrs {
		clean = append(clean, RedactAttr(attr))
	}

	return redactingHandler{next: h.next.WithAttrs(clean)}
}

func (h redactingHandler) WithGroup(name string) slog.Handler {
	return redactingHandler{next: h.next.WithGroup(name)}
}

func RedactAttr(attr slog.Attr) slog.Attr {
	if isSensitiveKey(attr.Key) {
		return slog.String(attr.Key, redactedValue)
	}

	if attr.Value.Kind() == slog.KindGroup {
		group := attr.Value.Group()
		clean := make([]slog.Attr, 0, len(group))
		for _, child := range group {
			clean = append(clean, RedactAttr(child))
		}

		return slog.Group(attr.Key, attrsToAny(clean)...)
	}

	return attr
}

func attrsToAny(attrs []slog.Attr) []any {
	values := make([]any, 0, len(attrs))
	for _, attr := range attrs {
		values = append(values, attr)
	}

	return values
}

func isSensitiveKey(key string) bool {
	key = strings.ToLower(key)
	if key == "" {
		return false
	}

	sensitiveParts := []string{
		"scannerkey",
		"scanner_key",
		"uploadtoken",
		"upload_token",
		"nonce",
		"password",
		"token",
	}

	for _, part := range sensitiveParts {
		if strings.Contains(key, part) {
			return true
		}
	}

	return false
}
