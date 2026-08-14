package config

import "testing"

func TestLoadUsesDefaults(t *testing.T) {
	t.Setenv("SIDERASCAN_API_URL", "")

	cfg := Load(BuildInfo{})

	if cfg.APIBaseURL != DefaultAPIBaseURL {
		t.Fatalf("expected default API base URL, got %q", cfg.APIBaseURL)
	}
	if cfg.Version != DefaultVersion {
		t.Fatalf("expected default version, got %q", cfg.Version)
	}
	if cfg.BuildMode != DefaultBuildMode {
		t.Fatalf("expected default build mode, got %q", cfg.BuildMode)
	}
}

func TestLoadReadsAPIBaseURLFromEnv(t *testing.T) {
	t.Setenv("SIDERASCAN_API_URL", "http://localhost:5000/")

	cfg := Load(BuildInfo{Version: "0.2.0", BuildMode: "prod"})

	if cfg.APIBaseURL != "http://localhost:5000" {
		t.Fatalf("expected normalized env API base URL, got %q", cfg.APIBaseURL)
	}
	if cfg.Version != "0.2.0" {
		t.Fatalf("expected build version, got %q", cfg.Version)
	}
	if cfg.BuildMode != "prod" {
		t.Fatalf("expected build mode, got %q", cfg.BuildMode)
	}
}

func TestLoadUsesBuildAPIBaseURLWhenEnvMissing(t *testing.T) {
	t.Setenv("SIDERASCAN_API_URL", "")

	cfg := Load(BuildInfo{APIBaseURL: "https://api.example.com/"})

	if cfg.APIBaseURL != "https://api.example.com" {
		t.Fatalf("expected build API base URL, got %q", cfg.APIBaseURL)
	}
}

func TestLoadReadsDemoModeFromEnv(t *testing.T) {
	t.Setenv("SIDERASCAN_DEMO_MODE", "true")

	cfg := Load(BuildInfo{})

	if !cfg.DemoMode {
		t.Fatal("expected demo mode to be enabled")
	}
}

func TestValidateForRuntimeRejectsProductionHTTPRemote(t *testing.T) {
	t.Setenv("SIDERASCAN_API_URL", "")
	cfg := Load(BuildInfo{BuildMode: "production", APIBaseURL: "http://example.com"})

	if err := ValidateForRuntime(cfg); err == nil {
		t.Fatal("expected production HTTP remote URL to be rejected")
	}
}

func TestValidateForRuntimeAcceptsProductionHTTPS(t *testing.T) {
	t.Setenv("SIDERASCAN_API_URL", "")
	cfg := Load(BuildInfo{BuildMode: "prod", APIBaseURL: "https://api.example.com"})

	if err := ValidateForRuntime(cfg); err != nil {
		t.Fatalf("expected production HTTPS URL to pass, got %v", err)
	}
}

func TestValidateForRuntimeAcceptsInternalLocalHTTP(t *testing.T) {
	t.Setenv("SIDERASCAN_API_URL", "")
	cfg := Load(BuildInfo{BuildMode: "internal", APIBaseURL: "http://localhost:4000"})

	if err := ValidateForRuntime(cfg); err != nil {
		t.Fatalf("expected internal local HTTP URL to pass, got %v", err)
	}
}

func TestValidateForRuntimeRejectsProductionLocalHTTP(t *testing.T) {
	t.Setenv("SIDERASCAN_API_URL", "")
	cfg := Load(BuildInfo{BuildMode: "production", APIBaseURL: "http://localhost:4000"})

	if err := ValidateForRuntime(cfg); err == nil {
		t.Fatal("expected production local HTTP URL to be rejected")
	}
}
