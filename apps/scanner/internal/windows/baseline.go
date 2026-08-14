package windows

import (
	"context"
	"time"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

const (
	MaxProcessRows      = 350
	MaxExecutableHashMB = 100
)

type BaselineOptions struct {
	StartedAt         time.Time
	Rules             []contract.ScannerRule
	AdvancedForensics contract.AdvancedForensicsConfig
}

type BaselineSnapshot struct {
	ProcessTimeline      []map[string]any
	Utilities            []map[string]any
	WindowsItems         []map[string]any
	LoadedModules        []map[string]any
	ProcessHandles       []map[string]any
	Services             []map[string]any
	Drivers              []map[string]any
	PersistenceItems     []map[string]any
	AF3Summary           map[string]any
	EventLogs            []map[string]any
	DefenderEvents       []map[string]any
	AF4Summary           map[string]any
	ExecutionArtifacts   []map[string]any
	AF5Summary           map[string]any
	FileLogs             []contract.FileLog
	FileTriage           []map[string]any
	NetworkConnections   []map[string]any
	DNSCache             []map[string]any
	HostsEntries         []map[string]any
	AF6Summary           map[string]any
	ForensicTimeline     []map[string]any
	AF7Summary           map[string]any
	Evidence             []contract.Evidence
	Findings             []contract.Finding
	StringCandidateFiles []string
	PartialErrors        []string
	WarningKeys          []string
}

func CollectBaseline(ctx context.Context, options BaselineOptions) BaselineSnapshot {
	return collectBaseline(ctx, options)
}

type RuleMatch struct {
	Matched    bool
	RuleID     string
	Category   string
	Status     string
	Severity   string
	Confidence int
}

type utilityRule struct {
	ID           string
	Category     string
	Status       string
	Severity     string
	Confidence   int
	ProcessNames []string
	Contains     []string
}

var builtInUtilityRules = []utilityRule{
	{
		ID:           "builtin_debugger_x64dbg",
		Category:     "debugger",
		Status:       "suspicious",
		Severity:     "WARNING",
		Confidence:   80,
		ProcessNames: []string{"x64dbg.exe", "x32dbg.exe", "ollydbg.exe"},
		Contains:     []string{"x64dbg", "x32dbg", "ollydbg"},
	},
	{
		ID:           "builtin_debugger_reverse_engineering",
		Category:     "debugger",
		Status:       "review",
		Severity:     "WARNING",
		Confidence:   65,
		ProcessNames: []string{"ida.exe", "ida64.exe", "ghidra.exe", "dnspy.exe", "dnspy-net-win64.exe"},
		Contains:     []string{"\\ida", "\\ghidra", "\\dnspy"},
	},
	{
		ID:           "builtin_memory_editor_cheat_engine",
		Category:     "memory_editor",
		Status:       "suspicious",
		Severity:     "WARNING",
		Confidence:   85,
		ProcessNames: []string{"cheatengine.exe", "cheatengine-x86_64.exe", "cheatengine-i386.exe"},
		Contains:     []string{"cheat engine", "cheatengine"},
	},
	{
		ID:           "builtin_injector_common",
		Category:     "injector",
		Status:       "suspicious",
		Severity:     "WARNING",
		Confidence:   80,
		ProcessNames: []string{"extreme injector.exe", "process injector.exe", "injector.exe"},
		Contains:     []string{"injector"},
	},
	{
		ID:           "builtin_macro_tools",
		Category:     "macro",
		Status:       "review",
		Severity:     "WARNING",
		Confidence:   60,
		ProcessNames: []string{"tinytask.exe", "macrorecorder.exe", "autohotkey.exe", "pulover.exe"},
		Contains:     []string{"tinytask", "macro recorder", "autohotkey", "pulover"},
	},
	{
		ID:           "builtin_remote_control",
		Category:     "remote_control",
		Status:       "review",
		Severity:     "WARNING",
		Confidence:   55,
		ProcessNames: []string{"anydesk.exe", "teamviewer.exe", "rustdesk.exe", "screenconnect.clientservice.exe"},
		Contains:     []string{"anydesk", "teamviewer", "rustdesk", "screenconnect"},
	},
	{
		ID:           "builtin_process_tool",
		Category:     "process_tool",
		Status:       "review",
		Severity:     "INFO",
		Confidence:   45,
		ProcessNames: []string{"processhacker.exe", "procexp.exe", "procexp64.exe", "procexp64a.exe", "procmon.exe"},
		Contains:     []string{"process hacker", "procexp", "procmon"},
	},
	{
		ID:           "builtin_tamper_tool",
		Category:     "tamper_tool",
		Status:       "suspicious",
		Severity:     "WARNING",
		Confidence:   75,
		ProcessNames: []string{"psexec.exe", "sc.exe", "autoruns.exe", "autorunsc.exe"},
		Contains:     []string{"autoruns", "autorunsc", "psexec"},
	},
}
