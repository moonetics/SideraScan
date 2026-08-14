package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

const (
	DefaultAPIBaseURL = "http://localhost:4000"
	DefaultVersion    = "0.1.0"
	DefaultBuildMode  = "dev"
)

type BuildInfo struct {
	Version    string
	Commit     string
	BuildTime  string
	BuildMode  string
	APIBaseURL string
}

type Config struct {
	APIBaseURL string
	Version    string
	BuildMode  string
	Commit     string
	BuildTime  string
	DemoMode   bool
}

func Load(info BuildInfo) Config {
	return Config{
		APIBaseURL: normalizeURL(envOrDefault("SIDERASCAN_API_URL", valueOrDefault(info.APIBaseURL, DefaultAPIBaseURL))),
		Version:    valueOrDefault(info.Version, DefaultVersion),
		BuildMode:  valueOrDefault(info.BuildMode, DefaultBuildMode),
		Commit:     valueOrDefault(info.Commit, "dev"),
		BuildTime:  valueOrDefault(info.BuildTime, "unknown"),
		DemoMode:   parseBool(os.Getenv("SIDERASCAN_DEMO_MODE")),
	}
}

func envOrDefault(name string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}

	return value
}

func valueOrDefault(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}

	return value
}

func normalizeURL(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return DefaultAPIBaseURL
	}

	return strings.TrimRight(value, "/")
}

func parseBool(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

var ErrInsecureProductionAPIURL = errors.New("production scanner requires an HTTPS API URL")

func ValidateForRuntime(cfg Config) error {
	if !IsProductionBuildMode(cfg.BuildMode) {
		return nil
	}

	parsed, err := url.Parse(cfg.APIBaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("%w: invalid URL", ErrInsecureProductionAPIURL)
	}
	if parsed.Scheme == "https" {
		return nil
	}

	return ErrInsecureProductionAPIURL
}

func IsProductionBuildMode(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "prod" || value == "production"
}
