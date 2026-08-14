package app

import (
	"log/slog"

	"github.com/moonetics/SideraScan/apps/scanner/internal/config"
	scannerui "github.com/moonetics/SideraScan/apps/scanner/internal/ui"
)

func Run(cfg config.Config, logger *slog.Logger) {
	scannerui.Run(cfg, logger)
}

func RunConfigError(cfg config.Config, logger *slog.Logger, err error) {
	scannerui.RunConfigError(cfg, logger, err)
}
