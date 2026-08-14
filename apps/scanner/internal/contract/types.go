package contract

import "time"

type ValidateKeyRequest struct {
	ScannerKey     string `json:"scannerKey"`
	ScannerVersion string `json:"scannerVersion"`
	Platform       string `json:"platform"`
	Arch           string `json:"arch"`
	PlayerLabel    string `json:"playerLabel,omitempty"`
}

type ConsentScope struct {
	ProcessList  bool `json:"processList"`
	FileMetadata bool `json:"fileMetadata"`
	Screenshot   bool `json:"screenshot"`
}

type ValidateKeyResponse struct {
	Valid          bool         `json:"valid"`
	ErrorCode      string       `json:"errorCode,omitempty"`
	Message        string       `json:"message,omitempty"`
	AccountID      string       `json:"accountId,omitempty"`
	AccountName    string       `json:"accountName,omitempty"`
	ScanSessionID  string       `json:"scanSessionId,omitempty"`
	UploadToken    string       `json:"uploadToken,omitempty"`
	Nonce          string       `json:"nonce,omitempty"`
	ExpiresAt      time.Time    `json:"expiresAt,omitempty"`
	EnabledModules []string     `json:"enabledModules,omitempty"`
	ConsentScope   ConsentScope `json:"consentScope,omitempty"`
}

type ScannerConfigRequest struct {
	ScannerKey     string `json:"scannerKey"`
	ScannerVersion string `json:"scannerVersion"`
}

type ScannerRule struct {
	ID           string         `json:"id"`
	Scope        string         `json:"scope"`
	AccountID    *string        `json:"accountId"`
	Name         string         `json:"name"`
	Type         string         `json:"type"`
	Category     string         `json:"category"`
	Severity     string         `json:"severity"`
	ManagedBy    string         `json:"managedBy,omitempty"`
	ManagedRefID string         `json:"managedRefId,omitempty"`
	RuleConfig   map[string]any `json:"ruleConfig"`
	UpdatedAt    time.Time      `json:"updatedAt"`
}

type ScannerConfigResponse struct {
	Status            string                  `json:"status"`
	AccountID         string                  `json:"accountId"`
	AccountName       string                  `json:"accountName"`
	ScannerVersion    string                  `json:"scannerVersion"`
	AdvancedForensics AdvancedForensicsConfig `json:"advancedForensics,omitempty"`
	Rules             []ScannerRule           `json:"rules"`
}

type AdvancedForensicsConfig struct {
	Enabled                 bool                     `json:"enabled"`
	ReviewMode              string                   `json:"reviewMode,omitempty"`
	Modules                 AdvancedForensicsModules `json:"modules,omitempty"`
	MaxRowsPerModule        int                      `json:"maxRowsPerModule,omitempty"`
	MaxFileHashMB           int                      `json:"maxFileHashMB,omitempty"`
	MaxPayloadBytes         int                      `json:"maxPayloadBytes,omitempty"`
	MaxTimelineRows         int                      `json:"maxTimelineRows,omitempty"`
	BrowserDownloadHistory  bool                     `json:"browserDownloadHistory"`
	DiscordTelegramMetadata bool                     `json:"discordTelegramMetadata"`
}

type AdvancedForensicsModules struct {
	LoadedModules      bool `json:"loadedModules"`
	ProcessHandles     bool `json:"processHandles"`
	Services           bool `json:"services"`
	Drivers            bool `json:"drivers"`
	PersistenceItems   bool `json:"persistenceItems"`
	EventLogs          bool `json:"eventLogs"`
	DefenderEvents     bool `json:"defenderEvents"`
	ExecutionArtifacts bool `json:"executionArtifacts"`
	FileTriage         bool `json:"fileTriage"`
	NetworkConnections bool `json:"networkConnections"`
	DNSCache           bool `json:"dnsCache"`
	HostsEntries       bool `json:"hostsEntries"`
	ForensicTimeline   bool `json:"forensicTimeline"`
}

type ScannerSession struct {
	AccountID      string
	AccountName    string
	ScanSessionID  string
	UploadToken    string
	Nonce          string
	ExpiresAt      time.Time
	EnabledModules []string
	ConsentScope   ConsentScope
	Config         ScannerConfigResponse
	ConfigPartial  bool
	ConfigWarnings []string
}

type ModuleResult struct {
	ModuleName   string `json:"moduleName"`
	Status       string `json:"status"`
	DurationMs   int64  `json:"durationMs,omitempty"`
	ErrorCode    string `json:"errorCode,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

type Finding struct {
	Category     string         `json:"category,omitempty"`
	Severity     string         `json:"severity,omitempty"`
	Title        string         `json:"title"`
	Message      string         `json:"message"`
	RuleID       string         `json:"ruleId,omitempty"`
	EvidenceRef  string         `json:"evidenceRef,omitempty"`
	Confidence   int            `json:"confidence,omitempty"`
	SourceModule string         `json:"sourceModule,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

type Evidence struct {
	ClientEvidenceID string         `json:"clientEvidenceId,omitempty"`
	Type             string         `json:"type"`
	Title            string         `json:"title"`
	Data             map[string]any `json:"data,omitempty"`
	StorageRef       string         `json:"storageRef,omitempty"`
}

type DeviceFingerprint struct {
	Hash       string `json:"hash"`
	Version    string `json:"version"`
	Confidence string `json:"confidence"`
}

type LauncherProfile struct {
	ProfileName    string         `json:"profileName"`
	LauncherType   string         `json:"launcherType"`
	Version        string         `json:"version,omitempty"`
	Channel        string         `json:"channel,omitempty"`
	Path           string         `json:"path,omitempty"`
	ExecutableHash string         `json:"executableHash,omitempty"`
	Publisher      string         `json:"publisher,omitempty"`
	Status         string         `json:"status,omitempty"`
	Tags           []string       `json:"tags,omitempty"`
	InstallTime    string         `json:"installTime,omitempty"`
	UpdateTime     string         `json:"updateTime,omitempty"`
	LastLaunchTime string         `json:"lastLaunchTime,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type ClientModAsset struct {
	Name           string         `json:"name"`
	SourceLauncher string         `json:"sourceLauncher,omitempty"`
	Path           string         `json:"path,omitempty"`
	FileCount      int            `json:"fileCount,omitempty"`
	TotalSize      int64          `json:"totalSize,omitempty"`
	CreatedTime    string         `json:"createdTime,omitempty"`
	ModifiedTime   string         `json:"modifiedTime,omitempty"`
	Status         string         `json:"status,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type ProcessTime struct {
	ProcessName string         `json:"processName"`
	Path        string         `json:"path,omitempty"`
	FirstSeenAt string         `json:"firstSeenAt,omitempty"`
	LastSeenAt  string         `json:"lastSeenAt,omitempty"`
	StartedAt   string         `json:"startedAt,omitempty"`
	EndedAt     string         `json:"endedAt,omitempty"`
	DurationMs  int64          `json:"durationMs,omitempty"`
	Source      string         `json:"source,omitempty"`
	Status      string         `json:"status,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type FileLog struct {
	Action         string         `json:"action"`
	Path           string         `json:"path,omitempty"`
	OldPath        string         `json:"oldPath,omitempty"`
	NewPath        string         `json:"newPath,omitempty"`
	Timestamp      string         `json:"timestamp,omitempty"`
	Source         string         `json:"source,omitempty"`
	Confidence     int            `json:"confidence,omitempty"`
	RelatedProcess string         `json:"relatedProcess,omitempty"`
	Severity       string         `json:"severity,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type UploadResultsRequest struct {
	UploadToken        string             `json:"uploadToken"`
	Nonce              string             `json:"nonce"`
	ScannerVersion     string             `json:"scannerVersion,omitempty"`
	StartedAt          string             `json:"startedAt,omitempty"`
	FinishedAt         string             `json:"finishedAt,omitempty"`
	Overview           map[string]any     `json:"overview,omitempty"`
	SystemIdentity     map[string]any     `json:"systemIdentity,omitempty"`
	NetworkSnapshot    map[string]any     `json:"networkSnapshot,omitempty"`
	Integrity          map[string]any     `json:"integrity,omitempty"`
	DeviceFingerprint  *DeviceFingerprint `json:"deviceFingerprint,omitempty"`
	Modules            []ModuleResult     `json:"modules,omitempty"`
	ProcessTimeline    []map[string]any   `json:"processTimeline,omitempty"`
	ExploreFiles       []map[string]any   `json:"exploreFiles,omitempty"`
	Utilities          []map[string]any   `json:"utilities,omitempty"`
	WindowsItems       []map[string]any   `json:"windowsItems,omitempty"`
	LauncherProfiles   []LauncherProfile  `json:"launcherProfiles,omitempty"`
	ClientModAssets    []ClientModAsset   `json:"clientModAssets,omitempty"`
	ProcessTimes       []ProcessTime      `json:"processTimes,omitempty"`
	FileLogs           []FileLog          `json:"fileLogs,omitempty"`
	LoadedModules      []map[string]any   `json:"loadedModules,omitempty"`
	ProcessHandles     []map[string]any   `json:"processHandles,omitempty"`
	Services           []map[string]any   `json:"services,omitempty"`
	Drivers            []map[string]any   `json:"drivers,omitempty"`
	PersistenceItems   []map[string]any   `json:"persistenceItems,omitempty"`
	EventLogs          []map[string]any   `json:"eventLogs,omitempty"`
	DefenderEvents     []map[string]any   `json:"defenderEvents,omitempty"`
	ExecutionArtifacts []map[string]any   `json:"executionArtifacts,omitempty"`
	FileTriage         []map[string]any   `json:"fileTriage,omitempty"`
	NetworkConnections []map[string]any   `json:"networkConnections,omitempty"`
	DNSCache           []map[string]any   `json:"dnsCache,omitempty"`
	HostsEntries       []map[string]any   `json:"hostsEntries,omitempty"`
	ForensicTimeline   []map[string]any   `json:"forensicTimeline,omitempty"`
	Evidence           []Evidence         `json:"evidence,omitempty"`
	Findings           []Finding          `json:"findings,omitempty"`
	AuditLog           []map[string]any   `json:"auditLog,omitempty"`
}

type UploadResultsResponse struct {
	Status         string `json:"status"`
	ScanSessionID  string `json:"scanSessionId"`
	StoredFindings int    `json:"storedFindings"`
}

type UploadResultSectionRequest struct {
	UploadToken string `json:"uploadToken"`
	Nonce       string `json:"nonce"`
	Section     string `json:"section"`
	Items       []any  `json:"items,omitempty"`
	Data        any    `json:"data,omitempty"`
	TotalItems  int    `json:"totalItems,omitempty"`
	ChunkIndex  int    `json:"chunkIndex"`
	ChunkCount  int    `json:"chunkCount"`
	PayloadHash string `json:"payloadHash,omitempty"`
	Status      string `json:"status,omitempty"`
	ErrorCode   string `json:"errorCode,omitempty"`
}

type UploadResultSectionResponse struct {
	Status        string `json:"status"`
	ScanSessionID string `json:"scanSessionId"`
	Section       string `json:"section"`
	UploadedItems int    `json:"uploadedItems"`
}

type CompleteSessionRequest struct {
	UploadToken string             `json:"uploadToken"`
	Nonce       string             `json:"nonce"`
	Status      string             `json:"status"`
	Telemetry   *CompleteTelemetry `json:"telemetry,omitempty"`
}

type CompleteTelemetry struct {
	UploadDurationMs     int64  `json:"uploadDurationMs,omitempty"`
	UploadAttemptCount   int    `json:"uploadAttemptCount,omitempty"`
	CompleteAttemptCount int    `json:"completeAttemptCount,omitempty"`
	LastErrorCode        string `json:"lastErrorCode,omitempty"`
	ScannerVersion       string `json:"scannerVersion,omitempty"`
}

type CompleteSessionResponse struct {
	Status        string `json:"status"`
	ScanSessionID string `json:"scanSessionId"`
	ScanStatus    string `json:"scanStatus"`
}
