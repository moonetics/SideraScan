package ui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image/color"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	fyneapp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	scannerassets "github.com/moonetics/SideraScan/apps/scanner/assets"
	scannerapi "github.com/moonetics/SideraScan/apps/scanner/internal/api"
	"github.com/moonetics/SideraScan/apps/scanner/internal/config"
	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
	scannerdetections "github.com/moonetics/SideraScan/apps/scanner/internal/detections"
	"github.com/moonetics/SideraScan/apps/scanner/internal/payload"
	"github.com/moonetics/SideraScan/apps/scanner/internal/progress"
	scannerroblox "github.com/moonetics/SideraScan/apps/scanner/internal/roblox"
	"github.com/moonetics/SideraScan/apps/scanner/internal/scan"
	"github.com/moonetics/SideraScan/apps/scanner/internal/scannerconfig"
	"github.com/moonetics/SideraScan/apps/scanner/internal/storage"
	"github.com/moonetics/SideraScan/apps/scanner/internal/windowchrome"
	scannerwindows "github.com/moonetics/SideraScan/apps/scanner/internal/windows"
)

const requestTimeout = 20 * time.Second
const scannerWindowTitle = "SideraScan by SideraLabs"
const scannerFooterText = "Developed by Squad Limpul © 2026. All rights reserved."

type pendingUpload struct {
	Request              contract.UploadResultsRequest
	PayloadHash          string
	ScanStatus           string
	CompactRetried       bool
	RetryCount           int
	UploadAttemptCount   int
	CompleteAttemptCount int
	UploadDurationMs     int64
	LastErrorCode        string
	CacheAvailable       bool
	CacheError           string
}

type windowDragHandle struct {
	widget.BaseWidget
	content fyne.CanvasObject
	active  bool
}

func newWindowDragHandle(content fyne.CanvasObject) *windowDragHandle {
	handle := &windowDragHandle{content: content}
	handle.ExtendBaseWidget(handle)
	return handle
}

func (h *windowDragHandle) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(h.content)
}

func (h *windowDragHandle) Dragged(event *fyne.DragEvent) {
	if event == nil {
		return
	}
	h.active = true
	windowchrome.BeginDrag(scannerWindowTitle)
}

func (h *windowDragHandle) DragEnd() {
	h.active = false
}

type smoothProgress struct {
	bar     *widget.ProgressBar
	mu      sync.Mutex
	current float64
	target  float64
	done    chan struct{}
}

func newSmoothProgress(bar *widget.ProgressBar) *smoothProgress {
	progress := &smoothProgress{
		bar:  bar,
		done: make(chan struct{}),
	}
	bar.SetValue(0)

	go progress.run()

	return progress
}

func (p *smoothProgress) SetTarget(target float64) {
	if p == nil {
		return
	}

	target = clampFloat(target, 0, 1)
	p.mu.Lock()
	if target > p.target {
		p.target = target
	}
	p.mu.Unlock()
}

func (p *smoothProgress) Stop() {
	if p == nil {
		return
	}

	select {
	case <-p.done:
	default:
		close(p.done)
	}
}

func (p *smoothProgress) WaitFor(target float64, timeout time.Duration) {
	if p == nil {
		return
	}

	target = clampFloat(target, 0, 1)
	deadline := time.After(timeout)
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

	for {
		p.mu.Lock()
		current := p.current
		p.mu.Unlock()
		if current >= target {
			return
		}

		select {
		case <-deadline:
			return
		case <-ticker.C:
		}
	}
}

func (p *smoothProgress) run() {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			p.mu.Lock()
			diff := p.target - p.current
			if diff > 0 {
				step := 0.004
				if diff > 0.08 {
					step = 0.008
				}
				if diff < step {
					step = diff
				}
				p.current += step
				current := p.current
				p.mu.Unlock()
				fyne.Do(func() {
					p.bar.SetValue(current)
				})
				continue
			}
			p.mu.Unlock()
		}
	}
}

func clampFloat(value float64, min float64, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func Run(cfg config.Config, logger *slog.Logger) {
	application := fyneapp.NewWithID("com.siderascan.scanner")
	application.Settings().SetTheme(NewTheme())
	apiClient := scannerapi.New(cfg.APIBaseURL, logger)
	if err := storage.NewDefaultRetryCache().CleanupExpired(); err != nil && logger != nil {
		logger.Warn("retry cache cleanup failed", "errorCode", "CACHE_CLEANUP_FAILED")
	}

	window := newScannerWindow(application, logger)
	window.SetContent(buildSplashScreen(window, cfg))

	transition := fyne.NewAnimation(2600*time.Millisecond, func(progress float32) {
		if progress >= 1 {
			window.SetContent(buildKeyInputScreen(window, cfg, logger, apiClient))
		}
	})
	transition.Curve = fyne.AnimationEaseOut
	transition.Start()

	window.Show()
	finalizeScannerWindow(window, logger)
	application.Run()
}

func RunConfigError(cfg config.Config, logger *slog.Logger, err error) {
	_ = logger
	application := fyneapp.NewWithID("com.siderascan.scanner")
	application.Settings().SetTheme(NewTheme())

	window := newScannerWindow(application, logger)

	title := widget.NewLabel("Configuration blocked")
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter
	message := widget.NewLabel("Production scanner builds require a secure HTTPS API endpoint. Please use a signed production build configured for the official SideraScan API.")
	if err != nil && !config.IsProductionBuildMode(cfg.BuildMode) {
		message.SetText("Scanner configuration could not be loaded.")
	}
	message.Wrapping = fyne.TextWrapWord
	message.Alignment = fyne.TextAlignCenter
	closeButton := widget.NewButton("Close", func() {
		window.Close()
	})
	closeButton.Importance = widget.HighImportance

	window.SetContent(buildScannerCard(window, container.NewVBox(title, message, closeButton)))
	window.Show()
	finalizeScannerWindow(window, logger)
	application.Run()
}

func newScannerWindow(application fyne.App, logger *slog.Logger) fyne.Window {
	var window fyne.Window
	if desktopDriver, ok := application.Driver().(desktop.Driver); ok {
		window = desktopDriver.CreateSplashWindow()
		window.SetTitle(scannerWindowTitle)
	} else {
		window = application.NewWindow(scannerWindowTitle)
	}

	window.SetPadded(false)
	window.Resize(fyne.NewSize(460, 300))
	window.SetFixedSize(true)
	window.CenterOnScreen()

	if !windowchrome.ApplyFrameless(scannerWindowTitle) && logger != nil {
		logger.Debug("native frameless helper unavailable")
	}

	return window
}

func finalizeScannerWindow(window fyne.Window, logger *slog.Logger) {
	window.CenterOnScreen()
	if !windowchrome.ApplyFrameless(scannerWindowTitle) && logger != nil {
		logger.Debug("native frameless helper unavailable after show")
	}
}

func buildSplashScreen(window fyne.Window, cfg config.Config) fyne.CanvasObject {
	_ = cfg
	loading := widget.NewLabel("Loading secure scanner...")
	loading.Alignment = fyne.TextAlignCenter

	tip := widget.NewLabel("Tip: click Start Scan to validate your key and begin a secure scan session.")
	tip.Alignment = fyne.TextAlignCenter
	tip.Wrapping = fyne.TextWrapWord

	return buildScannerCard(window, container.NewVBox(loading, widget.NewProgressBarInfinite(), tip))
}

func buildKeyInputScreen(window fyne.Window, cfg config.Config, logger *slog.Logger, apiClient *scannerapi.Client) fyne.CanvasObject {
	statusLabel := widget.NewLabel(StatusMessage(WaitingForKey))
	statusLabel.Wrapping = fyne.TextWrapWord
	statusLabel.Importance = widget.MediumImportance

	keyInput := widget.NewEntry()
	keyInput.SetPlaceHolder("sds_live_XXXX-XXXX-XXXX-XXXX-XXXX")

	clearButton := widget.NewButton("Clear", func() {
		keyInput.SetText("")
		statusLabel.SetText(StatusMessage(WaitingForKey))
	})

	var startButton *widget.Button
	startButton = widget.NewButton("Start Scan", func() {
		scannerKey := strings.TrimSpace(keyInput.Text)
		logger.Info("scanner start requested", "keyLength", len(scannerKey))
		if cfg.DemoMode {
			showDemoFlow(window)
			return
		}
		startScannerFlow(window, cfg, logger, apiClient, scannerKey)
	})
	startButton.Importance = widget.HighImportance
	startButton.Disable()

	keyInput.OnChanged = func(value string) {
		if strings.TrimSpace(value) == "" {
			startButton.Disable()
			statusLabel.SetText(StatusMessage(WaitingForKey))
		} else {
			startButton.Enable()
			statusLabel.SetText("Ready to scan.")
		}
	}

	formGroup := container.NewVBox(
		statusLabel,
		keyInput,
		container.NewGridWithColumns(2, clearButton, startButton),
	)

	return buildScannerCard(window, container.NewVBox(widget.NewLabel(""), formGroup))
}

func startScannerFlow(
	window fyne.Window,
	cfg config.Config,
	logger *slog.Logger,
	apiClient *scannerapi.Client,
	scannerKey string,
) {
	if scannerKey == "" {
		return
	}

	loadingStatus, loadingAnimation := showValidationLoading(window, "Validating key...")

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		defer cancel()

		validated, err := apiClient.ValidateKey(ctx, contract.ValidateKeyRequest{
			ScannerKey:     scannerKey,
			ScannerVersion: cfg.Version,
			Platform:       runtime.GOOS,
			Arch:           runtime.GOARCH,
		})
		if err != nil {
			showKeyInputError(window, cfg, logger, apiClient, scannerKey, loadingAnimation, userFacingAPIError(err))
			return
		}

		if !validated.Valid {
			showKeyInputError(window, cfg, logger, apiClient, scannerKey, loadingAnimation, userFacingValidationError(validated.ErrorCode, validated.Message))
			return
		}

		fyne.Do(func() {
			loadingStatus.SetText("Key valid. Fetching scanner config...")
		})

		scannerConfig, err := apiClient.GetScannerConfig(ctx, contract.ScannerConfigRequest{
			ScannerKey:     scannerKey,
			ScannerVersion: cfg.Version,
		})
		if err != nil {
			showKeyInputError(window, cfg, logger, apiClient, scannerKey, loadingAnimation, "Scanner config unavailable. Try again.")
			return
		}

		configValidation, err := scannerconfig.ValidateResponse(contract.ScannerSession{
			AccountID: validated.AccountID,
		}, scannerConfig, cfg.Version)
		if err != nil {
			showKeyInputError(window, cfg, logger, apiClient, scannerKey, loadingAnimation, "Scanner config was rejected. Validate key again.")
			return
		}
		scannerConfig = configValidation.Config

		session := contract.ScannerSession{
			AccountID:      validated.AccountID,
			AccountName:    validated.AccountName,
			ScanSessionID:  validated.ScanSessionID,
			UploadToken:    validated.UploadToken,
			Nonce:          validated.Nonce,
			ExpiresAt:      validated.ExpiresAt,
			EnabledModules: validated.EnabledModules,
			ConsentScope:   validated.ConsentScope,
			Config:         scannerConfig,
			ConfigPartial:  configValidation.Partial,
			ConfigWarnings: configValidation.Warnings,
		}

		logger.Info(
			"scanner session prepared",
			"scanSessionId", session.ScanSessionID,
			"accountId", session.AccountID,
			"enabledModules", len(session.EnabledModules),
			"rules", len(session.Config.Rules),
			"configPartial", session.ConfigPartial,
		)

		fyne.Do(func() {
			loadingStatus.SetText("Scanner config ready. Starting scan...")
			loadingAnimation.Stop()
			runBasicScan(window, cfg, logger, apiClient, session, contract.UploadResultsRequest{})
		})
	}()
}

func showKeyInputError(window fyne.Window, cfg config.Config, logger *slog.Logger, apiClient *scannerapi.Client, scannerKey string, loadingAnimation *fyne.Animation, message string) {
	fyne.Do(func() {
		loadingAnimation.Stop()
		window.SetContent(buildKeyInputScreenWithInitial(window, cfg, logger, apiClient, message, scannerKey))
	})
}

func buildKeyInputScreenWithInitial(window fyne.Window, cfg config.Config, logger *slog.Logger, apiClient *scannerapi.Client, status string, key string) fyne.CanvasObject {
	screen := buildKeyInputScreen(window, cfg, logger, apiClient)

	if status == "" && key == "" {
		return screen
	}

	statusLabel := widget.NewLabel(textOrFallback(status, StatusMessage(WaitingForKey)))
	statusLabel.Wrapping = fyne.TextWrapWord
	statusLabel.Importance = widget.MediumImportance

	keyInput := widget.NewEntry()
	keyInput.SetPlaceHolder("sds_live_XXXX-XXXX-XXXX-XXXX-XXXX")
	keyInput.SetText(key)

	clearButton := widget.NewButton("Clear", func() {
		keyInput.SetText("")
		statusLabel.SetText(StatusMessage(WaitingForKey))
	})

	var startButton *widget.Button
	startButton = widget.NewButton("Start Scan", func() {
		scannerKey := strings.TrimSpace(keyInput.Text)
		logger.Info("scanner start requested", "keyLength", len(scannerKey))
		if cfg.DemoMode {
			showDemoFlow(window)
			return
		}
		startScannerFlow(window, cfg, logger, apiClient, scannerKey)
	})
	startButton.Importance = widget.HighImportance
	if strings.TrimSpace(key) == "" {
		startButton.Disable()
	}

	keyInput.OnChanged = func(value string) {
		if strings.TrimSpace(value) == "" {
			startButton.Disable()
			statusLabel.SetText(StatusMessage(WaitingForKey))
		} else {
			startButton.Enable()
			if status == "" || status == StatusMessage(WaitingForKey) {
				statusLabel.SetText("Ready to scan.")
			}
		}
	}

	formGroup := container.NewVBox(
		statusLabel,
		keyInput,
		container.NewGridWithColumns(2, clearButton, startButton),
	)

	return buildScannerCard(window, container.NewVBox(widget.NewLabel(""), formGroup))
}

func showValidationLoading(window fyne.Window, message string) (*widget.Label, *fyne.Animation) {
	animationPanel, animation := buildArtifactScanner()
	statusLabel := widget.NewLabel(message)
	statusLabel.Alignment = fyne.TextAlignCenter

	window.SetContent(buildScannerCard(window, container.NewVBox(
		container.NewCenter(animationPanel),
		statusLabel,
		widget.NewProgressBarInfinite(),
	)))
	animation.Start()

	return statusLabel, animation
}

func buildArtifactScanner() (fyne.CanvasObject, *fyne.Animation) {
	lane := canvas.NewRectangle(colorPanelSoft)
	lane.SetMinSize(fyne.NewSize(390, 86))

	searchIcon := widget.NewIcon(theme.SearchIcon())
	searchIcon.Resize(fyne.NewSize(34, 34))
	searchIcon.Move(fyne.NewPos(18, 18))

	artifactText := canvas.NewText("Prefetch", colorAccentStrong)
	artifactText.TextSize = 12
	artifactText.TextStyle = fyne.TextStyle{Monospace: true, Bold: true}
	artifactText.Move(fyne.NewPos(58, 26))

	binaryText := canvas.NewText("01010011 01000100 01010011", colorMuted)
	binaryText.TextSize = 10
	binaryText.TextStyle = fyne.TextStyle{Monospace: true}
	binaryText.Move(fyne.NewPos(58, 45))

	stage := container.NewWithoutLayout(lane, searchIcon, artifactText, binaryText)
	artifacts := []string{
		"Prefetch",
		"Process List",
		"Registry",
		"ShimCache",
		"Roblox",
		"Bloxstrap",
		"File Logs",
		"10110100",
	}

	animation := fyne.NewAnimation(1600*time.Millisecond, func(progress float32) {
		x := float32(18) + progress*250
		searchIcon.Move(fyne.NewPos(x, 18))
		artifactText.Move(fyne.NewPos(x+42, 24))
		binaryText.Move(fyne.NewPos(x+42, 44))

		index := int(progress * float32(len(artifacts)))
		if index >= len(artifacts) {
			index = len(artifacts) - 1
		}
		artifactText.Text = artifacts[index]
		artifactText.Refresh()
		binaryText.Refresh()
	})
	animation.AutoReverse = true
	animation.RepeatCount = fyne.AnimationRepeatForever
	animation.Curve = fyne.AnimationEaseInOut

	return stage, animation
}

func runBasicScan(window fyne.Window, cfg config.Config, logger *slog.Logger, apiClient *scannerapi.Client, session contract.ScannerSession, retryPayload contract.UploadResultsRequest) {
	cache := storage.NewDefaultRetryCache()
	_ = cache.CleanupExpired()
	runScanWithCache(window, cfg, logger, apiClient, cache, session, pendingUpload{Request: retryPayload})
}

func runScanWithCache(window fyne.Window, cfg config.Config, logger *slog.Logger, apiClient *scannerapi.Client, cache storage.RetryCache, session contract.ScannerSession, pending pendingUpload) {
	progressLabel := widget.NewLabel("Preparing scan modules...")
	progressLabel.Alignment = fyne.TextAlignCenter
	progressBar := widget.NewProgressBar()
	smoothBar := newSmoothProgress(progressBar)
	hashLabel := widget.NewLabel("Payload hash: pending")
	hashLabel.Alignment = fyne.TextAlignCenter
	retryLabel := widget.NewLabel(fmt.Sprintf("Upload retry count: %d", pending.RetryCount))
	retryLabel.Alignment = fyne.TextAlignCenter
	animationPanel, animation := buildArtifactScanner()

	window.SetContent(buildScannerCard(window, container.NewVBox(
		container.NewCenter(animationPanel),
		progressLabel,
		progressBar,
		hashLabel,
		retryLabel,
	)))
	animation.Start()

	go func() {
		defer func() {
			smoothBar.Stop()
			fyne.Do(func() {
				animation.Stop()
			})
		}()

		prepared := pending
		if prepared.Request.UploadToken == "" {
			var err error
			prepared, err = prepareUploadPayload(cfg, session, func(event progress.Event) {
				fyne.Do(func() {
					progressLabel.SetText(event.Message)
				})
				smoothBar.SetTarget(event.Percent / 100)
			})
			if err != nil {
				fyne.Do(func() {
					window.SetContent(buildFailedScreen(window, cfg, logger, apiClient, cache, session, prepared, "Failed to prepare scan payload."))
				})
				return
			}
		}

		fyne.Do(func() {
			if prepared.PayloadHash != "" {
				hashLabel.SetText("Payload hash ready: " + shortID(prepared.PayloadHash))
			}
			progressLabel.SetText("Uploading scan result...")
		})
		smoothBar.SetTarget(0.96)

		if isSessionExpired(session) {
			_ = cache.Delete(session.ScanSessionID)
			prepared.LastErrorCode = scannerapi.NormalizeUploadTokenExpired
			fyne.Do(func() {
				window.SetContent(buildFailedScreen(window, cfg, logger, apiClient, cache, session, prepared, "Upload session expired. Validate key again."))
			})
			return
		}

		applyUploadTelemetry(&prepared.Request, cfg, prepared)
		prepared = saveRetryPayload(logger, cache, session, prepared)

		uploadStarted := time.Now()
		var err error
		prepared, err = uploadPreparedResults(
			context.Background(),
			logger,
			apiClient,
			session,
			prepared,
			func(message string, percent float64) {
				fyne.Do(func() {
					progressLabel.SetText(message)
					retryLabel.SetText(fmt.Sprintf("Upload attempts: %d", prepared.UploadAttemptCount))
				})
				smoothBar.SetTarget(percent)
			},
		)
		if err != nil {
			logger.Warn("scanner result upload failed", "scanSessionId", session.ScanSessionID, "errorCode", prepared.LastErrorCode)
			fyne.Do(func() {
				window.SetContent(buildFailedScreen(window, cfg, logger, apiClient, cache, session, prepared, userFacingAPIError(err)))
			})
			return
		}
		if prepared.UploadDurationMs == 0 {
			prepared.UploadDurationMs = time.Since(uploadStarted).Milliseconds()
		}

		fyne.Do(func() {
			progressLabel.SetText("Completing scan session...")
		})
		smoothBar.SetTarget(0.99)

		if isSessionExpired(session) {
			_ = cache.Delete(session.ScanSessionID)
			prepared.LastErrorCode = scannerapi.NormalizeUploadTokenExpired
			fyne.Do(func() {
				window.SetContent(buildFailedScreen(window, cfg, logger, apiClient, cache, session, prepared, "Upload session expired. Validate key again."))
			})
			return
		}

		completeRequest := contract.CompleteSessionRequest{
			UploadToken: session.UploadToken,
			Nonce:       session.Nonce,
			Status:      textOrFallback(prepared.ScanStatus, "COMPLETED"),
			Telemetry: &contract.CompleteTelemetry{
				UploadDurationMs:     prepared.UploadDurationMs,
				UploadAttemptCount:   prepared.UploadAttemptCount,
				CompleteAttemptCount: prepared.CompleteAttemptCount + 1,
				LastErrorCode:        prepared.LastErrorCode,
				ScannerVersion:       cfg.Version,
			},
		}
		completeResponse, completeTelemetry, err := apiClient.CompleteSessionWithTelemetry(context.Background(), session.ScanSessionID, completeRequest)
		prepared.CompleteAttemptCount += completeTelemetry.Attempts
		prepared.LastErrorCode = textOrFallback(completeTelemetry.LastCode, scannerapi.NormalizeErrorCode(err))
		if err != nil {
			logger.Warn("scanner session complete failed", "scanSessionId", session.ScanSessionID, "errorCode", prepared.LastErrorCode, "attempts", completeTelemetry.Attempts)
			fyne.Do(func() {
				window.SetContent(buildFailedScreen(window, cfg, logger, apiClient, cache, session, prepared, userFacingAPIError(err)))
			})
			return
		}

		_ = cache.Delete(session.ScanSessionID)
		logger.Info("scanner session completed", "scanSessionId", session.ScanSessionID, "scanStatus", completeResponse.ScanStatus)
		smoothBar.SetTarget(1)
		smoothBar.WaitFor(0.995, 1200*time.Millisecond)
		fyne.Do(func() {
			window.SetContent(buildCompletedScreen(window, session, completeResponse.ScanStatus))
		})
	}()
}

func uploadPreparedResults(
	ctx context.Context,
	logger *slog.Logger,
	apiClient *scannerapi.Client,
	session contract.ScannerSession,
	prepared pendingUpload,
	notify func(string, float64),
) (pendingUpload, error) {
	requestSize := payload.SizeBytes(prepared.Request)
	budget := uploadBudget(session)
	if requestSize > budget.MaxPayloadBytes {
		logger.Warn("scanner payload exceeds budget, using chunked upload", "scanSessionId", session.ScanSessionID, "payloadSizeBytes", requestSize, "budgetBytes", budget.MaxPayloadBytes)
		return uploadChunkedResults(ctx, logger, apiClient, session, prepared, notify)
	}

	_, uploadTelemetry, err := apiClient.UploadResultsWithTelemetry(ctx, session.ScanSessionID, prepared.Request)
	prepared.UploadAttemptCount += uploadTelemetry.Attempts
	prepared.UploadDurationMs += uploadTelemetry.DurationMs
	prepared.LastErrorCode = textOrFallback(uploadTelemetry.LastCode, scannerapi.NormalizeErrorCode(err))
	if notify != nil {
		notify("Uploading scan result...", 0.97)
	}
	if err == nil {
		return prepared, nil
	}

	if !isBodyTooLargeError(err) {
		return prepared, err
	}

	logger.Warn("scanner single upload too large, falling back to chunked upload", "scanSessionId", session.ScanSessionID)
	if notify != nil {
		notify("Scan result is too large. Switching to section upload...", 0.965)
	}
	prepared.CompactRetried = true
	prepared.LastErrorCode = scannerapi.NormalizeRequestBodyTooLarge
	return uploadChunkedResults(ctx, logger, apiClient, session, prepared, notify)
}

func uploadChunkedResults(
	ctx context.Context,
	logger *slog.Logger,
	apiClient *scannerapi.Client,
	session contract.ScannerSession,
	prepared pendingUpload,
	notify func(string, float64),
) (pendingUpload, error) {
	sections := payload.UploadSections(prepared.Request)
	sectionNames := payload.SectionNames(sections)
	core := payload.CoreUploadRequest(prepared.Request, sectionNames)
	if core.Integrity == nil {
		core.Integrity = map[string]any{}
	}
	core.Integrity["uploadMode"] = "chunked"
	core.Integrity["sectionUploadFailed"] = false

	if notify != nil {
		notify("Uploading core scan result...", 0.965)
	}
	_, telemetry, err := apiClient.UploadCoreResultsWithTelemetry(ctx, session.ScanSessionID, core)
	prepared.UploadAttemptCount += telemetry.Attempts
	prepared.UploadDurationMs += telemetry.DurationMs
	prepared.LastErrorCode = textOrFallback(telemetry.LastCode, scannerapi.NormalizeErrorCode(err))
	if err != nil {
		return prepared, err
	}

	failedSections := map[string]string{}
	totalSections := len(sections)
	for index, section := range sections {
		chunks := payload.SplitSection(section, payload.DefaultMaxSectionBytes)
		if len(chunks) == 0 {
			continue
		}
		for _, chunk := range chunks {
			if isSessionExpired(session) {
				prepared.LastErrorCode = scannerapi.NormalizeUploadTokenExpired
				return prepared, scannerapi.APIError{StatusCode: 401, Code: "UPLOAD_TOKEN_EXPIRED", Message: "Upload session expired"}
			}
			if notify != nil {
				message := fmt.Sprintf("Uploading section %d/%d: %s", index+1, totalSections, section.Name)
				if chunk.ChunkCount > 1 {
					message = fmt.Sprintf("%s chunk %d/%d", message, chunk.ChunkIndex+1, chunk.ChunkCount)
				}
				notify(message, 0.965+(float64(index)/float64(maxInt(totalSections, 1)))*0.025)
			}
			req := contract.UploadResultSectionRequest{
				UploadToken: session.UploadToken,
				Nonce:       session.Nonce,
				Section:     chunk.Section,
				Items:       chunk.Items,
				TotalItems:  chunk.TotalItems,
				ChunkIndex:  chunk.ChunkIndex,
				ChunkCount:  chunk.ChunkCount,
				PayloadHash: chunk.PayloadHash,
				Status:      "uploaded",
			}
			_, telemetry, err = apiClient.UploadResultSectionWithTelemetry(ctx, session.ScanSessionID, req)
			prepared.UploadAttemptCount += telemetry.Attempts
			prepared.UploadDurationMs += telemetry.DurationMs
			prepared.LastErrorCode = textOrFallback(telemetry.LastCode, scannerapi.NormalizeErrorCode(err))
			if err != nil {
				errorCode := textOrFallback(scannerapi.NormalizeErrorCode(err), scannerapi.NormalizeUploadFailed)
				failedSections[section.Name] = errorCode
				logger.Warn("scanner section upload failed", "scanSessionId", session.ScanSessionID, "section", section.Name, "errorCode", errorCode)
				markSectionUploadFailed(ctx, apiClient, session, section.Name, errorCode, chunk.TotalItems, chunk.ChunkIndex, chunk.ChunkCount)
				break
			}
		}
	}

	if len(failedSections) > 0 {
		prepared.ScanStatus = "PARTIAL"
		if prepared.Request.Integrity == nil {
			prepared.Request.Integrity = map[string]any{}
		}
		prepared.Request.Integrity["sectionUploadFailed"] = true
		prepared.Request.Integrity["sectionUploadStatus"] = failedSections
		prepared.LastErrorCode = scannerapi.NormalizeUploadFailed
	}
	return prepared, nil
}

func markSectionUploadFailed(ctx context.Context, apiClient *scannerapi.Client, session contract.ScannerSession, section string, errorCode string, totalItems int, chunkIndex int, chunkCount int) {
	_, _, _ = apiClient.UploadResultSectionWithTelemetry(ctx, session.ScanSessionID, contract.UploadResultSectionRequest{
		UploadToken: session.UploadToken,
		Nonce:       session.Nonce,
		Section:     section,
		TotalItems:  totalItems,
		ChunkIndex:  chunkIndex,
		ChunkCount:  chunkCount,
		Status:      "failed",
		ErrorCode:   errorCode,
	})
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func prepareUploadPayload(cfg config.Config, session contract.ScannerSession, emit func(progress.Event)) (pendingUpload, error) {
	tracker := progress.NewTracker()
	startedAt := time.Now().UTC()
	var snapshot scannerwindows.Snapshot
	var baseline scannerwindows.BaselineSnapshot
	var robloxSnapshot scannerroblox.Snapshot
	var detectionResult scannerdetections.Result
	runner := scan.NewRunner([]scan.Module{
		{
			Name:  "overview",
			Stage: progress.StageOverview,
			Run: func(ctx context.Context, runCtx scan.RunContext) error {
				snapshot = scannerwindows.CollectSnapshot(ctx, scannerwindows.CollectOptions{
					ScanSessionID: session.ScanSessionID,
					StartedAt:     startedAt,
					FinishedAt:    time.Now().UTC(),
				})
				if len(snapshot.PartialErrors) > 0 {
					return scan.Warning("overview collector completed with limited fields")
				}
				return nil
			},
		},
		{
			Name:  "device_fingerprint",
			Stage: progress.StageDeviceFingerprint,
			Run: func(ctx context.Context, runCtx scan.RunContext) error {
				_ = ctx
				_ = runCtx
				if snapshot.DeviceFingerprint == nil || snapshot.DeviceFingerprint.Hash == "" {
					return errors.New("device fingerprint unavailable")
				}
				if snapshot.DeviceFingerprint.Confidence == "LOW" {
					return errors.New("device fingerprint low confidence")
				}
				return nil
			},
		},
		{
			Name:  "process_timeline",
			Stage: progress.StageProcessTimeline,
			Run: func(ctx context.Context, runCtx scan.RunContext) error {
				_ = runCtx
				baseline = scannerwindows.CollectBaseline(ctx, scannerwindows.BaselineOptions{
					StartedAt:         startedAt,
					Rules:             session.Config.Rules,
					AdvancedForensics: session.Config.AdvancedForensics,
				})
				if len(baseline.PartialErrors) > 0 {
					return errors.New("process timeline collector partial")
				}
				if len(baseline.WarningKeys) > 0 {
					return scan.Warning("windows baseline completed with limited artifacts")
				}
				return nil
			},
		},
		{
			Name:  "roblox_modules",
			Stage: progress.StageRobloxModules,
			Run: func(ctx context.Context, runCtx scan.RunContext) error {
				_ = runCtx
				if baseline.ProcessTimeline == nil {
					baseline = scannerwindows.CollectBaseline(ctx, scannerwindows.BaselineOptions{
						StartedAt:         startedAt,
						Rules:             session.Config.Rules,
						AdvancedForensics: session.Config.AdvancedForensics,
					})
				}
				robloxSnapshot = scannerroblox.Collect(ctx, scannerroblox.Options{
					StartedAt:       startedAt,
					ProcessTimeline: baseline.ProcessTimeline,
				})
				if len(robloxSnapshot.PartialErrors) > 0 {
					return scan.Warning("roblox module completed with limited artifacts")
				}
				return nil
			},
		},
		{
			Name:  "file_logs",
			Stage: progress.StageFileLogs,
			Run: func(ctx context.Context, runCtx scan.RunContext) error {
				_ = ctx
				_ = runCtx
				if robloxSnapshot.FileLogs == nil {
					robloxSnapshot = scannerroblox.Collect(context.Background(), scannerroblox.Options{
						StartedAt:       startedAt,
						ProcessTimeline: baseline.ProcessTimeline,
					})
				}
				if len(robloxSnapshot.PartialErrors) > 0 {
					return scan.Warning("roblox file logs completed with limited artifacts")
				}
				return nil
			},
		},
		{
			Name:  "utilities_windows_items",
			Stage: progress.StageUtilitiesWindowsItems,
			Run: func(ctx context.Context, runCtx scan.RunContext) error {
				_ = ctx
				_ = runCtx
				if baseline.ProcessTimeline == nil {
					baseline = scannerwindows.CollectBaseline(context.Background(), scannerwindows.BaselineOptions{
						StartedAt:         startedAt,
						Rules:             session.Config.Rules,
						AdvancedForensics: session.Config.AdvancedForensics,
					})
				}
				if len(baseline.PartialErrors) > 0 {
					return errors.New("windows baseline collector partial")
				}
				if len(baseline.WarningKeys) > 0 {
					return scan.Warning("windows items completed with limited artifacts")
				}
				return nil
			},
		},
		{
			Name:  "custom_detections",
			Stage: progress.StageCustomDetections,
			Run: func(ctx context.Context, runCtx scan.RunContext) error {
				_ = runCtx
				if len(session.Config.Rules) == 0 {
					detectionResult = scannerdetections.Result{}
					return nil
				}
				detectionPayload := payload.BuildBasicResult(session, cfg.Version, startedAt, time.Now().UTC())
				applyBaselineSnapshot(&detectionPayload, baseline)
				applyRobloxSnapshot(&detectionPayload, robloxSnapshot)
				detectionResult = scannerdetections.Evaluate(ctx, scannerdetections.Input{
					Rules:                session.Config.Rules,
					Payload:              detectionPayload,
					StringCandidateFiles: scannerStringCandidates(baseline, robloxSnapshot),
				})
				if detectionResult.InvalidRuleCount > 0 || len(detectionResult.PartialErrors) > 0 {
					return errors.New("custom detections partial")
				}
				return nil
			},
		},
	})
	moduleResults := runner.Run(context.Background(), scan.RunContext{
		Session: session,
		Version: cfg.Version,
		Started: startedAt,
	}, tracker, func(event scan.Event) {
		if emit != nil {
			emit(event.Progress)
		}
	})
	finishedAt := time.Now().UTC()

	if emit != nil {
		emit(tracker.Advance(progress.StageNormalization, 0, "Normalizing scan result..."))
	}

	request := payload.BuildBasicResult(session, cfg.Version, startedAt, finishedAt)
	if snapshot.Overview == nil {
		snapshot = scannerwindows.CollectSnapshot(context.Background(), scannerwindows.CollectOptions{
			ScanSessionID: session.ScanSessionID,
			StartedAt:     startedAt,
			FinishedAt:    finishedAt,
		})
	}
	applySystemSnapshot(&request, snapshot, startedAt, finishedAt)
	applyBaselineSnapshot(&request, baseline)
	applyRobloxSnapshot(&request, robloxSnapshot)
	applyDetectionResult(&request, detectionResult)
	request.Modules = scan.ToContractModules(moduleResults)
	if len(baseline.AF7Summary) > 0 {
		request.Modules = append(request.Modules, contract.ModuleResult{
			ModuleName: "forensic_timeline_correlation",
			Status:     "completed",
		})
	}
	if session.ConfigPartial {
		request.Modules = append(request.Modules, contract.ModuleResult{
			ModuleName:   "scanner_config",
			Status:       "partial",
			ErrorCode:    "CONFIG_PARTIAL",
			ErrorMessage: "Scanner config was partially applied.",
		})
	}
	request.AuditLog = append(request.AuditLog, moduleAuditLogs(moduleResults, finishedAt)...)
	if session.ConfigPartial {
		request.AuditLog = append(request.AuditLog, map[string]any{
			"action":    "scanner_config_partial",
			"source":    "siderascan_scanner",
			"warnings":  session.ConfigWarnings,
			"createdAt": time.Now().UTC().Format(time.RFC3339),
		})
	}

	payload.ApplyForensicNoiseTuning(&request)

	sanitizedRequest, err := payload.SanitizeForUpload(request)
	if err != nil {
		return pendingUpload{}, err
	}
	request = sanitizedRequest
	collectedIntegrity := request.Integrity

	budget := uploadBudget(session)
	if request.Integrity == nil {
		request.Integrity = map[string]any{}
	}
	request.Integrity["payloadSizeBytes"] = payload.SizeBytes(request)
	request.Integrity["payloadBudget"] = map[string]any{"maxPayloadBytes": budget.MaxPayloadBytes}
	if payload.SizeBytes(request) <= budget.MaxPayloadBytes {
		compactReport := payload.CompactForBudget(&request, budget)
		if compactReport.Trimmed {
			request.AuditLog = append(request.AuditLog, map[string]any{
				"action":            "payload_compacted",
				"source":            "siderascan_scanner",
				"originalSizeBytes": compactReport.OriginalSizeBytes,
				"finalSizeBytes":    compactReport.FinalSizeBytes,
				"trimmedSections":   compactReport.TrimmedSections,
				"createdAt":         time.Now().UTC().Format(time.RFC3339),
			})
		}
	}

	payloadHash, err := payload.HashUploadPayload(request)
	if err != nil {
		return pendingUpload{}, err
	}

	request.Integrity = map[string]any{
		"payloadHash":     payloadHash,
		"hashAlgorithm":   "sha256",
		"hashScope":       "upload_payload_without_upload_secrets",
		"moduleRunStatus": scan.OverallStatus(moduleResults),
	}
	mergeMap(request.Integrity, collectedIntegrity)
	if session.ConfigPartial {
		request.Integrity["scannerConfigPartial"] = true
		request.Integrity["scannerConfigWarnings"] = session.ConfigWarnings
	}
	request.AuditLog = append(request.AuditLog, map[string]any{
		"action":      "payload_hashed",
		"source":      "siderascan_scanner",
		"payloadHash": payloadHash,
		"createdAt":   time.Now().UTC().Format(time.RFC3339),
	})

	if emit != nil {
		emit(tracker.Advance(progress.StageNormalization, 1, "Payload hash ready."))
	}

	return pendingUpload{
		Request:     request,
		PayloadHash: payloadHash,
		ScanStatus:  overallStatusWithConfig(moduleResults, session.ConfigPartial),
	}, nil
}

func overallStatusWithConfig(results []scan.ModuleResult, configPartial bool) string {
	if configPartial {
		return "PARTIAL"
	}
	return scan.OverallStatus(results)
}

func applySystemSnapshot(request *contract.UploadResultsRequest, snapshot scannerwindows.Snapshot, startedAt time.Time, finishedAt time.Time) {
	request.Overview = snapshot.Overview
	request.SystemIdentity = snapshot.SystemIdentity
	request.NetworkSnapshot = snapshot.NetworkSnapshot
	request.DeviceFingerprint = snapshot.DeviceFingerprint
	request.Integrity = snapshot.Integrity

	if request.Overview == nil {
		request.Overview = map[string]any{}
	}
	request.Overview["scanSpeed"] = formatDuration(finishedAt.Sub(startedAt))
	request.Overview["date"] = finishedAt.UTC().Format(time.RFC3339)

	if request.SystemIdentity == nil {
		request.SystemIdentity = map[string]any{}
	}
	if request.Integrity == nil {
		request.Integrity = map[string]any{}
	}
}

func applyBaselineSnapshot(request *contract.UploadResultsRequest, baseline scannerwindows.BaselineSnapshot) {
	if baseline.ProcessTimeline != nil {
		request.ProcessTimeline = baseline.ProcessTimeline
	}
	if baseline.Utilities != nil {
		request.Utilities = baseline.Utilities
	}
	if baseline.WindowsItems != nil {
		request.WindowsItems = baseline.WindowsItems
	}
	if baseline.LoadedModules != nil {
		request.LoadedModules = baseline.LoadedModules
	}
	if baseline.ProcessHandles != nil {
		request.ProcessHandles = baseline.ProcessHandles
	}
	if baseline.Services != nil {
		request.Services = baseline.Services
	}
	if baseline.Drivers != nil {
		request.Drivers = baseline.Drivers
	}
	if baseline.PersistenceItems != nil {
		request.PersistenceItems = baseline.PersistenceItems
	}
	if baseline.EventLogs != nil {
		request.EventLogs = baseline.EventLogs
	}
	if baseline.DefenderEvents != nil {
		request.DefenderEvents = baseline.DefenderEvents
	}
	if baseline.ExecutionArtifacts != nil {
		request.ExecutionArtifacts = baseline.ExecutionArtifacts
	}
	if len(baseline.FileLogs) > 0 {
		request.FileLogs = append(request.FileLogs, baseline.FileLogs...)
	}
	if baseline.FileTriage != nil {
		request.FileTriage = baseline.FileTriage
	}
	if baseline.NetworkConnections != nil {
		request.NetworkConnections = baseline.NetworkConnections
	}
	if baseline.DNSCache != nil {
		request.DNSCache = baseline.DNSCache
	}
	if baseline.HostsEntries != nil {
		request.HostsEntries = baseline.HostsEntries
	}
	if baseline.ForensicTimeline != nil {
		request.ForensicTimeline = baseline.ForensicTimeline
	}
	if len(baseline.Evidence) > 0 {
		request.Evidence = append(request.Evidence, baseline.Evidence...)
	}
	if len(baseline.Findings) > 0 {
		request.Findings = append(request.Findings, baseline.Findings...)
	}
	if request.Integrity == nil {
		request.Integrity = map[string]any{}
	}
	if len(baseline.PartialErrors) > 0 {
		request.Integrity["windowsBaselinePartial"] = true
		request.Integrity["windowsBaselineErrorKeys"] = baseline.PartialErrors
	}
	if len(baseline.WarningKeys) > 0 {
		request.Integrity["windowsBaselineWarning"] = true
		request.Integrity["windowsBaselineWarningKeys"] = baseline.WarningKeys
	}
	if len(baseline.AF3Summary) > 0 {
		request.Integrity["af3Summary"] = baseline.AF3Summary
	}
	if len(baseline.AF4Summary) > 0 {
		request.Integrity["af4Summary"] = baseline.AF4Summary
	}
	if len(baseline.AF5Summary) > 0 {
		request.Integrity["af5Summary"] = baseline.AF5Summary
	}
	if len(baseline.AF6Summary) > 0 {
		request.Integrity["af6Summary"] = baseline.AF6Summary
	}
	if len(baseline.AF7Summary) > 0 {
		request.Integrity["af7Summary"] = baseline.AF7Summary
	}
}

func applyRobloxSnapshot(request *contract.UploadResultsRequest, snapshot scannerroblox.Snapshot) {
	if snapshot.LauncherProfiles != nil {
		request.LauncherProfiles = snapshot.LauncherProfiles
	}
	if snapshot.ClientModAssets != nil {
		request.ClientModAssets = snapshot.ClientModAssets
	}
	if snapshot.ProcessTimes != nil {
		request.ProcessTimes = snapshot.ProcessTimes
	}
	if snapshot.FileLogs != nil {
		request.FileLogs = append(request.FileLogs, snapshot.FileLogs...)
	}
	if request.Integrity == nil {
		request.Integrity = map[string]any{}
	}
	if len(snapshot.PartialErrors) > 0 {
		request.Integrity["robloxModuleWarning"] = true
		request.Integrity["robloxModuleWarningKeys"] = snapshot.PartialErrors
	}
}

func applyDetectionResult(request *contract.UploadResultsRequest, result scannerdetections.Result) {
	if len(result.Findings) > 0 {
		request.Findings = append(request.Findings, result.Findings...)
	}
	if request.Integrity == nil {
		request.Integrity = map[string]any{}
	}
	request.Integrity["customDetectionRulesEvaluated"] = result.EvaluatedRules
	request.Integrity["customDetectionRulesMatched"] = result.MatchedRules
	if result.InvalidRuleCount > 0 || len(result.PartialErrors) > 0 {
		request.Integrity["customDetectionPartial"] = true
		request.Integrity["customDetectionInvalidRuleCount"] = result.InvalidRuleCount
		request.Integrity["customDetectionErrorKeys"] = result.PartialErrors
	}
}

func applyUploadTelemetry(request *contract.UploadResultsRequest, cfg config.Config, pending pendingUpload) {
	if request.Integrity == nil {
		request.Integrity = map[string]any{}
	}
	request.Integrity["telemetry"] = map[string]any{
		"scannerVersion":   cfg.Version,
		"uploadRetryCount": pending.RetryCount,
		"lastErrorCode":    pending.LastErrorCode,
		"payloadHash":      pending.PayloadHash,
	}
	request.AuditLog = append(request.AuditLog, map[string]any{
		"action":           "upload_prepared",
		"source":           "siderascan_scanner",
		"uploadRetryCount": pending.RetryCount,
		"lastErrorCode":    pending.LastErrorCode,
		"createdAt":        time.Now().UTC().Format(time.RFC3339),
	})
}

func scannerStringCandidates(baseline scannerwindows.BaselineSnapshot, robloxSnapshot scannerroblox.Snapshot) []string {
	candidates := make([]string, 0, len(baseline.StringCandidateFiles)+len(robloxSnapshot.StringCandidateFiles))
	candidates = append(candidates, baseline.StringCandidateFiles...)
	candidates = append(candidates, robloxSnapshot.StringCandidateFiles...)
	return candidates
}

func isSessionExpired(session contract.ScannerSession) bool {
	return !session.ExpiresAt.IsZero() && !session.ExpiresAt.After(time.Now())
}

func mergeMap(target map[string]any, source map[string]any) {
	for key, value := range source {
		if _, exists := target[key]; !exists {
			target[key] = value
		}
	}
}

func saveRetryPayload(logger *slog.Logger, cache storage.RetryCache, session contract.ScannerSession, pending pendingUpload) pendingUpload {
	payloadBytes, err := json.Marshal(pending.Request)
	if err != nil {
		pending.CacheError = "Retry cache unavailable."
		return pending
	}

	err = cache.Save(storage.CacheMetadata{
		ScanSessionID: session.ScanSessionID,
		AccountName:   session.AccountName,
		PayloadHash:   pending.PayloadHash,
		ExpiresAt:     session.ExpiresAt,
		RetryCount:    pending.RetryCount,
	}, payloadBytes)
	if err != nil {
		pending.CacheAvailable = false
		pending.CacheError = "Encrypted retry cache unavailable; retry works while this window stays open."
		if logger != nil {
			logger.Warn("retry cache save failed", "scanSessionId", session.ScanSessionID, "error", err.Error())
		}
		return pending
	}

	pending.CacheAvailable = true
	pending.CacheError = ""
	return pending
}

func loadRetryPayload(cache storage.RetryCache, session contract.ScannerSession, pending pendingUpload) (pendingUpload, error) {
	if pending.Request.UploadToken != "" {
		pending.RetryCount++
		return pending, nil
	}

	cached, err := cache.Load(session.ScanSessionID)
	if err != nil {
		return pendingUpload{}, err
	}

	var request contract.UploadResultsRequest
	if err := json.Unmarshal(cached.Payload, &request); err != nil {
		return pendingUpload{}, err
	}

	return pendingUpload{
		Request:        request,
		PayloadHash:    cached.Metadata.PayloadHash,
		ScanStatus:     "COMPLETED",
		RetryCount:     cached.Metadata.RetryCount + 1,
		CacheAvailable: true,
	}, nil
}

func moduleAuditLogs(results []scan.ModuleResult, timestamp time.Time) []map[string]any {
	entries := make([]map[string]any, 0, len(results))
	for _, result := range results {
		entries = append(entries, map[string]any{
			"action":     "module_completed",
			"source":     "siderascan_scanner",
			"moduleName": result.Name,
			"status":     string(result.Status),
			"durationMs": result.Duration.Milliseconds(),
			"createdAt":  timestamp.UTC().Format(time.RFC3339),
		})
	}

	return entries
}

func buildCompletedScreen(window fyne.Window, session contract.ScannerSession, scanStatus string) fyne.CanvasObject {
	title := widget.NewLabel(StatusMessage(Completed))
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter

	account := widget.NewLabel(fmt.Sprintf("Account: %s", valueOrUnknown(session.AccountName)))
	scanID := widget.NewLabel(fmt.Sprintf("Scan ID: %s", session.ScanSessionID))
	status := widget.NewLabel(fmt.Sprintf("Status: %s", valueOrUnknown(scanStatus)))

	copyButton := widget.NewButton("Copy Scan ID", func() {
		window.Clipboard().SetContent(session.ScanSessionID)
	})
	closeButton := widget.NewButton("Close", func() {
		window.Close()
	})
	closeButton.Importance = widget.HighImportance

	return buildScannerCard(window, container.NewVBox(
		title,
		account,
		scanID,
		status,
		container.NewGridWithColumns(2, copyButton, closeButton),
	))
}

func buildFailedScreen(window fyne.Window, cfg config.Config, logger *slog.Logger, apiClient *scannerapi.Client, cache storage.RetryCache, session contract.ScannerSession, pending pendingUpload, message string) fyne.CanvasObject {
	title := widget.NewLabel(StatusMessage(Failed))
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter

	expired := isSessionExpired(session)
	errorText := widget.NewLabel(message)
	errorText.Wrapping = fyne.TextWrapWord
	errorText.Alignment = fyne.TextAlignCenter
	errorCode := widget.NewLabel("Error code: " + textOrFallback(pending.LastErrorCode, "UNKNOWN"))
	errorCode.Alignment = fyne.TextAlignCenter
	retryCount := widget.NewLabel(fmt.Sprintf("Upload attempts: %d", pending.UploadAttemptCount))
	retryCount.Alignment = fyne.TextAlignCenter
	expiryText := "Upload token: valid"
	if expired {
		expiryText = "Upload token: expired"
	}
	tokenStatus := widget.NewLabel(expiryText)
	tokenStatus.Alignment = fyne.TextAlignCenter
	cacheText := widget.NewLabel(textOrFallback(pending.CacheError, "Retry payload is protected with Windows user encryption when available."))
	cacheText.Wrapping = fyne.TextWrapWord
	cacheText.Alignment = fyne.TextAlignCenter

	retryButton := widget.NewButton("Retry Upload", func() {
		if !session.ExpiresAt.IsZero() && time.Now().After(session.ExpiresAt) {
			_ = cache.Delete(session.ScanSessionID)
			window.SetContent(buildFailedScreen(window, cfg, logger, apiClient, cache, session, pendingUpload{}, "Upload session expired. Please validate the scanner key again."))
			return
		}

		next, err := loadRetryPayload(cache, session, pending)
		if err != nil {
			next = pending
			next.CacheError = "Retry cache could not be read. Please validate the scanner key again."
			window.SetContent(buildFailedScreen(window, cfg, logger, apiClient, cache, session, next, next.CacheError))
			return
		}

		runScanWithCache(window, cfg, logger, apiClient, cache, session, next)
	})
	retryButton.Importance = widget.HighImportance

	discardButton := widget.NewButton("Discard and Close", func() {
		_ = cache.Delete(session.ScanSessionID)
		window.Close()
	})
	startOverButton := widget.NewButton("Start Over", func() {
		_ = cache.Delete(session.ScanSessionID)
		window.SetContent(buildKeyInputScreen(window, cfg, logger, apiClient))
	})
	startOverButton.Importance = widget.HighImportance
	actions := container.NewGridWithColumns(2, discardButton, retryButton)
	if expired {
		actions = container.NewGridWithColumns(2, discardButton, startOverButton)
	}

	return buildScannerCard(window, container.NewVBox(
		title,
		errorText,
		errorCode,
		retryCount,
		tokenStatus,
		cacheText,
		actions,
	))
}

func buildHeader(cfg config.Config, showVersion bool) (fyne.CanvasObject, *canvas.Image) {
	logo := canvas.NewImageFromResource(scannerassets.Logo())
	logo.FillMode = canvas.ImageFillContain
	logo.SetMinSize(fyne.NewSize(72, 72))

	title := canvas.NewText(scannerWindowTitle, colorForeground)
	title.TextSize = 22
	title.TextStyle = fyne.TextStyle{Bold: true}

	subtitle := canvas.NewText("Secure scan session", colorMuted)
	subtitle.TextSize = 14

	headerItems := []fyne.CanvasObject{title, subtitle}
	if showVersion {
		versionText := canvas.NewText(fmt.Sprintf("Scanner %s", cfg.Version), colorMuted)
		versionText.TextSize = 12
		headerItems = append(headerItems, versionText)
	}

	headerText := container.NewVBox(headerItems...)
	header := container.NewHBox(logo, container.NewPadded(headerText))

	return header, logo
}

func buildScannerCard(window fyne.Window, body fyne.CanvasObject) fyne.CanvasObject {
	footer := widget.NewLabel(scannerFooterText)
	footer.Alignment = fyne.TextAlignCenter
	footer.Importance = widget.LowImportance

	cardContent := container.NewBorder(
		buildCompactHeader(window),
		footer,
		nil,
		nil,
		container.NewVBox(widget.NewSeparator(), body),
	)

	card := container.NewStack(
		canvas.NewRectangle(colorPanel),
		container.NewPadded(cardContent),
	)

	return container.NewStack(canvas.NewRectangle(colorBackground), container.NewPadded(card))
}

func buildCompactHeader(window fyne.Window) fyne.CanvasObject {
	logo := canvas.NewImageFromResource(scannerassets.Logo())
	logo.FillMode = canvas.ImageFillContain
	logo.SetMinSize(fyne.NewSize(30, 30))

	title := canvas.NewText(scannerWindowTitle, colorForeground)
	title.TextSize = 16
	title.TextStyle = fyne.TextStyle{Bold: true}

	closeButton := widget.NewButtonWithIcon("", theme.CancelIcon(), func() {
		window.Close()
	})
	closeButton.Importance = widget.LowImportance

	brand := container.NewHBox(logo, container.NewPadded(title))
	dragSurface := canvas.NewRectangle(color.NRGBA{A: 0})
	dragSurface.SetMinSize(fyne.NewSize(360, 42))
	dragArea := newWindowDragHandle(container.NewStack(dragSurface, container.NewPadded(brand)))

	return container.NewBorder(nil, nil, nil, closeButton, dragArea)
}

func showDemoFlow(window fyne.Window) {
	statusLabel, loadingAnimation := showValidationLoading(window, "Validating key...")

	go func() {
		time.Sleep(900 * time.Millisecond)
		fyne.Do(func() {
			statusLabel.SetText("Key valid. Fetching scanner config...")
		})

		time.Sleep(1100 * time.Millisecond)
		fyne.Do(func() {
			statusLabel.SetText("Scanner config ready. Starting scan...")
		})
		time.Sleep(500 * time.Millisecond)
		fyne.Do(func() {
			loadingAnimation.Stop()
			showDemoScanProgress(window)
		})
	}()
}

func showDemoScanProgress(window fyne.Window) {
	progressLabel := widget.NewLabel("Running overview")
	progressLabel.Alignment = fyne.TextAlignCenter
	progressBar := widget.NewProgressBar()
	smoothBar := newSmoothProgress(progressBar)
	hashLabel := widget.NewLabel("Payload hash: pending")
	hashLabel.Alignment = fyne.TextAlignCenter
	retryLabel := widget.NewLabel("Upload retry count: 0")
	retryLabel.Alignment = fyne.TextAlignCenter
	animationPanel, animation := buildArtifactScanner()

	window.SetContent(buildScannerCard(window, container.NewVBox(
		container.NewCenter(animationPanel),
		progressLabel,
		progressBar,
		hashLabel,
		retryLabel,
	)))
	animation.Start()

	go func() {
		steps := []struct {
			label   string
			percent float64
			delay   time.Duration
		}{
			{"Running overview", 0.30, 450 * time.Millisecond},
			{"Running device fingerprint", 0.40, 450 * time.Millisecond},
			{"Running process timeline", 0.55, 450 * time.Millisecond},
			{"Running Roblox modules", 0.72, 450 * time.Millisecond},
			{"Running file logs", 0.84, 450 * time.Millisecond},
			{"Running utilities and Windows items", 0.92, 450 * time.Millisecond},
			{"Normalizing scan result", 0.96, 450 * time.Millisecond},
			{"Uploading scan result", 0.99, 450 * time.Millisecond},
			{"Completing scan session", 1.00, 450 * time.Millisecond},
		}

		for _, step := range steps {
			time.Sleep(step.delay)
			fyne.Do(func() {
				progressLabel.SetText(step.label)
				if step.percent >= 0.96 {
					hashLabel.SetText("Payload hash ready: demo0...hash")
				}
			})
			smoothBar.SetTarget(step.percent)
		}

		smoothBar.WaitFor(0.995, 1200*time.Millisecond)
		fyne.Do(func() {
			smoothBar.Stop()
			animation.Stop()
			window.SetContent(buildCompletedScreen(window, contract.ScannerSession{
				AccountName:   "Demo Account",
				ScanSessionID: "demo-scan",
			}, "COMPLETED"))
		})
	}()
}

func userFacingValidationError(errorCode string, fallback string) string {
	switch errorCode {
	case "INVALID_KEY":
		return "Scanner key is invalid."
	case "KEY_REVOKED":
		return "Scanner key has been revoked."
	case "KEY_EXPIRED":
		return "Scanner key has expired."
	case "ACCOUNT_DISABLED":
		return "Account is not active."
	case "VERSION_NOT_ALLOWED":
		return "Scanner version is not allowed. Please download the latest scanner."
	default:
		if strings.TrimSpace(fallback) != "" {
			return fallback
		}
		return "Scanner key could not be validated."
	}
}

func userFacingAPIError(err error) string {
	if err == nil {
		return ""
	}

	if apiErr, ok := err.(scannerapi.APIError); ok {
		switch apiErr.Code {
		case "INVALID_KEY", "KEY_REVOKED", "KEY_EXPIRED", "ACCOUNT_DISABLED", "VERSION_NOT_ALLOWED":
			return userFacingValidationError(apiErr.Code, apiErr.Message)
		}
	}

	switch scannerapi.NormalizeErrorCode(err) {
	case scannerapi.NormalizeNetworkUnavailable, scannerapi.NormalizeServerUnavailable:
		return "Server unavailable. Try again."
	case scannerapi.NormalizeRequestTimeout:
		return "Request timed out. Try again."
	case scannerapi.NormalizeRateLimited:
		return "Too many requests. Wait a moment, then retry."
	case scannerapi.NormalizeRequestBodyTooLarge:
		return "Payload is still too large. Contact admin to increase API body limit."
	case scannerapi.NormalizeUploadTokenExpired:
		return "Upload session expired. Validate key again."
	case scannerapi.NormalizeUploadAuthFailed:
		return "Upload session was rejected. Validate key again."
	case scannerapi.NormalizeValidationFailed:
		return "Scanner key could not be validated."
	case scannerapi.NormalizeConfigUnavailable:
		return "Scanner config unavailable. Try again."
	}

	if apiErr, ok := err.(scannerapi.APIError); ok && strings.TrimSpace(apiErr.Message) != "" {
		return apiErr.Message
	}
	return "Request failed. Try again."
}

func isBodyTooLargeError(err error) bool {
	if err == nil {
		return false
	}
	if apiErr, ok := err.(scannerapi.APIError); ok && apiErr.StatusCode == 413 {
		return true
	}
	return scannerapi.NormalizeErrorCode(err) == scannerapi.NormalizeRequestBodyTooLarge
}

func uploadBudget(session contract.ScannerSession) payload.Budget {
	return payload.Budget{
		MaxPayloadBytes: session.Config.AdvancedForensics.MaxPayloadBytes,
		MaxTimelineRows: session.Config.AdvancedForensics.MaxTimelineRows,
	}
}

func shortID(value string) string {
	if len(value) <= 12 {
		return value
	}

	return value[:8] + "..." + value[len(value)-4:]
}

func valueOrUnknown(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "Unknown"
	}

	return value
}

func textOrFallback(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}

	return value
}

func formatDuration(duration time.Duration) string {
	seconds := int(duration.Round(time.Second).Seconds())
	if seconds < 1 {
		seconds = 1
	}

	return fmt.Sprintf("%ds", seconds)
}
