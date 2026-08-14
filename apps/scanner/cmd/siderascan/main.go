package main

import (
	"os"

	scannerapp "github.com/moonetics/SideraScan/apps/scanner/internal/app"
	"github.com/moonetics/SideraScan/apps/scanner/internal/config"
	"github.com/moonetics/SideraScan/apps/scanner/internal/logging"
)

var (
	version    = "0.1.0"
	commit     = "dev"
	buildTime  = "unknown"
	buildMode  = "dev"
	apiBaseURL = ""
)

func main() {
	cfg := config.Load(config.BuildInfo{
		Version:    version,
		Commit:     commit,
		BuildTime:  buildTime,
		BuildMode:  buildMode,
		APIBaseURL: apiBaseURL,
	})
	logger := logging.New(os.Stdout, cfg.BuildMode)

	if err := config.ValidateForRuntime(cfg); err != nil {
		logger.Error("scanner runtime configuration rejected", "error", err.Error(), "buildMode", cfg.BuildMode)
		scannerapp.RunConfigError(cfg, logger, err)
		return
	}

	logger.Info(
		"starting scanner ui",
		"version", cfg.Version,
		"buildMode", cfg.BuildMode,
		"apiBaseURL", cfg.APIBaseURL,
	)

	scannerapp.Run(cfg, logger)
}
