package scan

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
	"github.com/moonetics/SideraScan/apps/scanner/internal/progress"
)

type ModuleStatus string

const (
	StatusPending   ModuleStatus = "pending"
	StatusRunning   ModuleStatus = "running"
	StatusCompleted ModuleStatus = "completed"
	StatusPartial   ModuleStatus = "partial"
	StatusFailed    ModuleStatus = "failed"
)

type ModuleResult struct {
	Name         string
	Status       ModuleStatus
	Duration     time.Duration
	ErrorCode    string
	ErrorMessage string
}

type RunContext struct {
	Session contract.ScannerSession
	Version string
	Started time.Time
}

type Module struct {
	Name  string
	Stage progress.Stage
	Run   func(context.Context, RunContext) error
}

type WarningError struct {
	Message string
}

func (e WarningError) Error() string {
	return e.Message
}

func Warning(message string) error {
	message = strings.TrimSpace(message)
	if message == "" {
		message = "module completed with warnings"
	}
	return WarningError{Message: message}
}

type Event struct {
	Progress progress.Event
	Module   ModuleResult
}

type Runner struct {
	modules []Module
}

func NewRunner(modules []Module) Runner {
	return Runner{modules: modules}
}

func NewPlaceholderRunner() Runner {
	return NewRunner([]Module{
		{Name: "overview", Stage: progress.StageOverview},
		{Name: "device_fingerprint", Stage: progress.StageDeviceFingerprint},
		{Name: "process_timeline", Stage: progress.StageProcessTimeline},
		{Name: "roblox_modules", Stage: progress.StageRobloxModules},
		{Name: "file_logs", Stage: progress.StageFileLogs},
		{Name: "utilities_windows_items", Stage: progress.StageUtilitiesWindowsItems},
	})
}

func (r Runner) Run(ctx context.Context, runCtx RunContext, tracker *progress.Tracker, emit func(Event)) []ModuleResult {
	results := make([]ModuleResult, 0, len(r.modules))

	for _, module := range r.modules {
		started := time.Now()
		running := ModuleResult{Name: module.Name, Status: StatusRunning}
		if emit != nil {
			emit(Event{
				Progress: tracker.Advance(module.Stage, 0, "Running "+module.Name),
				Module:   running,
			})
		}

		err := runModule(ctx, module, runCtx)
		status := StatusCompleted
		errorCode := ""
		errorMessage := ""
		if err != nil {
			var warning WarningError
			if errors.As(err, &warning) {
				errorCode = "MODULE_WARNING"
			} else {
				status = StatusPartial
				errorCode = "MODULE_PARTIAL"
			}
			errorMessage = RedactError(err).Error()
		}

		result := ModuleResult{
			Name:         module.Name,
			Status:       status,
			Duration:     time.Since(started),
			ErrorCode:    errorCode,
			ErrorMessage: errorMessage,
		}
		results = append(results, result)

		if emit != nil {
			emit(Event{
				Progress: tracker.Advance(module.Stage, 1, "Completed "+module.Name),
				Module:   result,
			})
		}
	}

	return results
}

func ToContractModules(results []ModuleResult) []contract.ModuleResult {
	modules := make([]contract.ModuleResult, 0, len(results))
	for _, result := range results {
		modules = append(modules, contract.ModuleResult{
			ModuleName:   result.Name,
			Status:       string(result.Status),
			DurationMs:   result.Duration.Milliseconds(),
			ErrorCode:    result.ErrorCode,
			ErrorMessage: result.ErrorMessage,
		})
	}

	return modules
}

func OverallStatus(results []ModuleResult) string {
	for _, result := range results {
		if result.Status == StatusPartial || result.Status == StatusFailed {
			return "PARTIAL"
		}
	}

	return "COMPLETED"
}

func RedactError(err error) error {
	if err == nil {
		return nil
	}

	message := err.Error()
	replacements := []string{
		"scannerKey", "scanner key",
		"uploadToken", "upload token",
		"nonce",
		"password",
		"token",
		"MachineGuid",
		"serial",
	}
	for _, item := range replacements {
		message = strings.ReplaceAll(message, item, "[REDACTED]")
	}

	return errors.New(message)
}

func runModule(ctx context.Context, module Module, runCtx RunContext) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if module.Run == nil {
		time.Sleep(220 * time.Millisecond)
		return nil
	}

	return module.Run(ctx, runCtx)
}
