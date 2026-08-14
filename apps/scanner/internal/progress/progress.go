package progress

import "math"

type Stage string

const (
	StageInit                  Stage = "init"
	StageKeyValidation         Stage = "key_validation"
	StageConsent               Stage = "consent"
	StageScannerConfig         Stage = "scanner_config"
	StageOverview              Stage = "overview"
	StageDeviceFingerprint     Stage = "device_fingerprint"
	StageProcessTimeline       Stage = "process_timeline"
	StageRobloxModules         Stage = "roblox_modules"
	StageFileLogs              Stage = "file_logs"
	StageUtilitiesWindowsItems Stage = "utilities_windows_items"
	StageCustomDetections      Stage = "custom_detections"
	StageNormalization         Stage = "normalization"
	StageUpload                Stage = "upload"
	StageComplete              Stage = "complete"
)

type Range struct {
	Start float64
	End   float64
}

type Event struct {
	Stage   Stage
	Percent float64
	Message string
}

type Tracker struct {
	current float64
	ranges  map[Stage]Range
}

func NewTracker() *Tracker {
	return &Tracker{
		ranges: DefaultRanges(),
	}
}

func DefaultRanges() map[Stage]Range {
	return map[Stage]Range{
		StageInit:                  {Start: 0, End: 3},
		StageKeyValidation:         {Start: 3, End: 10},
		StageConsent:               {Start: 10, End: 12},
		StageScannerConfig:         {Start: 12, End: 18},
		StageOverview:              {Start: 18, End: 30},
		StageDeviceFingerprint:     {Start: 30, End: 40},
		StageProcessTimeline:       {Start: 40, End: 55},
		StageRobloxModules:         {Start: 55, End: 72},
		StageFileLogs:              {Start: 72, End: 84},
		StageUtilitiesWindowsItems: {Start: 84, End: 92},
		StageCustomDetections:      {Start: 92, End: 94},
		StageNormalization:         {Start: 94, End: 96},
		StageUpload:                {Start: 96, End: 99},
		StageComplete:              {Start: 99, End: 100},
	}
}

func (t *Tracker) Advance(stage Stage, fraction float64, message string) Event {
	rng, ok := t.ranges[stage]
	if !ok {
		rng = Range{Start: t.current, End: t.current}
	}

	fraction = clamp(fraction, 0, 1)
	next := rng.Start + (rng.End-rng.Start)*fraction
	next = clamp(next, 0, 100)
	if next < t.current {
		next = t.current
	}
	t.current = round(next)

	return Event{
		Stage:   stage,
		Percent: t.current,
		Message: message,
	}
}

func (t *Tracker) Current() float64 {
	return t.current
}

func clamp(value float64, min float64, max float64) float64 {
	return math.Max(min, math.Min(max, value))
}

func round(value float64) float64 {
	return math.Round(value*10) / 10
}
