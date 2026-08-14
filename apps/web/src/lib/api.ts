import { env } from "./env";

export type HealthResponse = {
  status: "ok";
  service: "api";
  database?: "ok" | "error";
};

export type AuthUser = {
  id: string;
  email: string;
  username: string;
  displayName: string;
  globalRole: "SUPER_ADMIN" | "USER";
  status: "ACTIVE" | "DISABLED";
};

export type AccountStatus = "ACTIVE" | "SUSPENDED" | "DELETED";
export type AccountRole = "ACCOUNT_OWNER" | "MODERATOR" | "VIEWER";
export type ScannerKeyStatus = "ACTIVE" | "REVOKED" | "EXPIRED";
export type DeviceMarkStatus = "BANNED" | "SUSPICIOUS" | "TRUSTED" | "CLEARED";
export type DeviceMarkScope = "GLOBAL" | "ACCOUNT";
export type FingerprintConfidence = "LOW" | "MEDIUM" | "HIGH";
export type DetectionRuleScope = "GLOBAL" | "ACCOUNT";
export type DetectionRuleType =
  | "PROCESS_NAME"
  | "FILE_HASH"
  | "PATH_PATTERN"
  | "STRING_SIGNATURE";
export type DetectionSampleStatus = "EXTRACTED" | "PURGED" | "FAILED";
export type AiRecommendedAction =
  | "NO_ACTION"
  | "MONITOR"
  | "REQUEST_RESCAN"
  | "MANUAL_REVIEW"
  | "ESCALATE";
export type AutomationEventStatus = "PENDING" | "SENT" | "FAILED" | "DISABLED";
export type MonitoringSeverity = "INFO" | "WARNING" | "HIGH" | "CRITICAL";
export type AlertNotificationStatus =
  | "PENDING"
  | "SENT"
  | "FAILED"
  | "DISABLED";
export type ScanStatus =
  | "CREATED"
  | "KEY_VALIDATED"
  | "CONSENT_ACCEPTED"
  | "RUNNING"
  | "UPLOADING"
  | "COMPLETED"
  | "PARTIAL"
  | "FAILED"
  | "PENDING_AI_REVIEW"
  | "AI_REVIEWED"
  | "PENDING_MODERATOR"
  | "NEEDS_RESCAN"
  | "CLEARED"
  | "FLAGGED"
  | "ESCALATED";
export type Severity = "INFO" | "CLEAN" | "WARNING" | "SEVERE" | "CRITICAL";
export type FindingCategory =
  | "OVERVIEW"
  | "DEVICE"
  | "PROCESS"
  | "FILE"
  | "FILE_LOG"
  | "UTILITY"
  | "WINDOWS_ITEM"
  | "LAUNCHER_PROFILE"
  | "CLIENT_MOD_ASSET"
  | "CUSTOM_DETECTION"
  | "INTEGRITY"
  | "NETWORK"
  | "AI";

export type AuthResponse = {
  user: AuthUser;
};

export type AccountListItem = {
  id: string;
  name: string;
  slug: string;
  status: AccountStatus;
  createdAt: string;
  updatedAt: string;
  memberCount: number;
  viewerRole: AccountRole | null;
};

export type SafeUser = AuthUser & {
  lastLoginAt?: string | null;
  createdAt?: string;
  updatedAt?: string;
  accountMemberships?: Array<{
    id: string;
    accountId: string;
    role: AccountRole;
    createdAt: string;
    account: {
      id: string;
      name: string;
      slug: string;
      status: AccountStatus;
    };
  }>;
  accountMembershipCount?: number;
  isAssigned?: boolean;
};

export type AccountDetail = AccountListItem & {
  users: Array<{
    id: string;
    role: AccountRole;
    createdAt: string;
    updatedAt: string;
    user: SafeUser;
  }>;
  auditLogs: Array<{
    id: string;
    accountId: string | null;
    actorUserId: string | null;
    action: string;
    entityType: string;
    entityId: string | null;
    before: unknown;
    after: unknown;
    createdAt: string;
  }>;
};

export type ScannerKeyListItem = {
  id: string;
  accountId: string;
  accountName: string;
  name: string;
  keyPrefix: string;
  status: ScannerKeyStatus;
  createdAt: string;
  updatedAt: string;
  lastUsedAt: string | null;
  usageCount: number;
  expiresAt: string | null;
  rateLimitPerHour: number;
  allowedScannerVersions: string[];
};

export type ScannerKeyRevealResponse = {
  scannerKey: ScannerKeyListItem;
  rawKey: string;
};

export type ScanListItem = {
  id: string;
  accountId: string;
  accountName: string;
  scannerKeyId: string;
  scannerKeyName: string;
  scannerKeyPrefix: string;
  playerLabel: string | null;
  status: ScanStatus;
  scannerVersion: string;
  platform: string;
  arch: string;
  startedAt: string | null;
  finishedAt: string | null;
  createdAt: string;
  expiresAt: string;
  riskScore: number;
  maxSeverity: Severity;
  reviewStatus: string;
  findingCount: number;
};

export type ScanDetail = ScanListItem & {
  device: DeviceSafeDetail | null;
  result: null | {
    id: string;
    payloadHash: string;
    overview: Record<string, unknown>;
    systemIdentity: Record<string, unknown>;
    networkSnapshot: Record<string, unknown>;
    integrity: Record<string, unknown>;
    processTimeline: unknown[];
    exploreFiles: unknown[];
    utilities: unknown[];
    windowsItems: unknown[];
    auditLog: unknown[];
    loadedModules: unknown[];
    processHandles: unknown[];
    services: unknown[];
    drivers: unknown[];
    persistenceItems: unknown[];
    eventLogs: unknown[];
    defenderEvents: unknown[];
    executionArtifacts: unknown[];
    fileTriage: unknown[];
    networkConnections: unknown[];
    dnsCache: unknown[];
    hostsEntries: unknown[];
    forensicTimeline: unknown[];
    createdAt: string;
  };
  modules: Array<{
    id: string;
    moduleName: string;
    status: string;
    durationMs: number | null;
    errorCode: string | null;
    errorMessage: string | null;
    createdAt: string;
  }>;
  evidence: Array<{
    id: string;
    clientEvidenceId: string | null;
    type: string;
    title: string;
    data: unknown;
    storageRef: string | null;
    createdAt: string;
  }>;
  launcherProfiles: Array<{
    id: string;
    profileName: string;
    launcherType: string;
    version: string | null;
    channel: string | null;
    pathMasked: string | null;
    executableHash: string | null;
    publisher: string | null;
    status: string;
    tags: unknown;
    installTime: string | null;
    updateTime: string | null;
    lastLaunchTime: string | null;
    metadata: unknown;
    createdAt: string;
  }>;
  clientModAssets: Array<{
    id: string;
    name: string;
    sourceLauncher: string | null;
    pathMasked: string | null;
    fileCount: number | null;
    totalSize: string | null;
    createdTime: string | null;
    modifiedTime: string | null;
    status: string;
    metadata: unknown;
    createdAt: string;
  }>;
  processTimes: Array<{
    id: string;
    processName: string;
    pathMasked: string | null;
    firstSeenAt: string | null;
    lastSeenAt: string | null;
    startedAt: string | null;
    endedAt: string | null;
    durationMs: number | null;
    source: string | null;
    status: string;
    metadata: unknown;
    createdAt: string;
  }>;
  fileLogs: Array<{
    id: string;
    action: string;
    pathMasked: string | null;
    oldPathMasked: string | null;
    newPathMasked: string | null;
    timestamp: string | null;
    source: string | null;
    confidence: number | null;
    relatedProcess: string | null;
    severity: Severity;
    metadata: unknown;
    createdAt: string;
  }>;
  auditLogs: Array<{
    id: string;
    accountId: string | null;
    actorUserId: string | null;
    action: string;
    entityType: string;
    entityId: string | null;
    before: unknown;
    after: unknown;
    createdAt: string;
  }>;
  aiReview: null | {
    id: string;
    assessment: string;
    confidence: number;
    summaryForModerator: string;
    summaryForPlayer: string | null;
    recommendedAction: AiRecommendedAction;
    keyIndicators: unknown;
    possibleFalsePositives: unknown;
    contradictions: unknown;
    moderatorChecklist: unknown;
    questionsForPlayer: unknown;
    evidenceReferences: unknown;
    model: string | null;
    promptVersion: string | null;
    inputHash: string | null;
    generatedAt: string;
    createdAt: string;
    updatedAt: string;
    evidenceLinks: Array<{
      id: string;
      findingId: string | null;
      evidenceId: string | null;
      finding: null | {
        id: string;
        title: string;
        severity: Severity;
      };
      evidence: null | {
        id: string;
        type: string;
        title: string;
      };
      createdAt: string;
    }>;
  };
  automationEvents: Array<{
    id: string;
    eventType: string;
    idempotencyKey: string;
    status: AutomationEventStatus;
    attemptCount: number;
    lastError: string | null;
    lastAttemptAt: string | null;
    createdAt: string;
    updatedAt: string;
  }>;
  findings: Array<{
    id: string;
    category: FindingCategory;
    severity: Severity;
    title: string;
    message: string;
    ruleId: string | null;
    evidenceId: string | null;
    evidence: null | {
      id: string;
      type: string;
      title: string;
    };
    confidence: number;
    sourceModule: string | null;
    metadata: unknown;
    createdAt: string;
  }>;
};

export type DeviceMark = {
  id: string;
  deviceId: string;
  scope: DeviceMarkScope;
  accountId: string | null;
  accountName: string | null;
  status: DeviceMarkStatus;
  severity: Severity;
  reason: string;
  markedAt: string;
  markedBy: null | { id: string; displayName: string };
  expiresAt: string | null;
  revokedAt: string | null;
  revokedBy?: null | { id: string; displayName: string };
  evidence: Array<{
    id: string;
    scanSessionId: string | null;
    findingId: string | null;
    note: string | null;
    createdAt: string;
  }>;
};

export type DeviceScanHistoryItem = Pick<
  ScanListItem,
  | "id"
  | "accountId"
  | "accountName"
  | "playerLabel"
  | "status"
  | "scannerVersion"
  | "riskScore"
  | "maxSeverity"
  | "startedAt"
  | "finishedAt"
  | "createdAt"
> & {
  scannerKeyName: string;
  scannerKeyPrefix: string;
  findingCount: number;
};

export type DeviceSafeDetail = {
  id: string;
  fingerprintPrefix: string;
  fingerprintVersion: string;
  fingerprintConfidence: FingerprintConfidence;
  firstSeenAt: string;
  lastSeenAt: string;
  scanCount: number;
  currentMark: DeviceMark | null;
};

export type DeviceListItem = DeviceSafeDetail & {
  accounts: Array<{
    id: string;
    name: string;
    slug: string;
    status: AccountStatus;
    scanCount: number;
    firstSeenAt: string;
    lastSeenAt: string;
  }>;
};

export type DeviceDetail = DeviceListItem & {
  marks: DeviceMark[];
  scanHistory: DeviceScanHistoryItem[];
};

export type DetectionRule = {
  id: string;
  accountId: string | null;
  accountName: string | null;
  scope: DetectionRuleScope;
  name: string;
  type: DetectionRuleType;
  category: FindingCategory;
  severity: Severity;
  enabled: boolean;
  managedBy: string | null;
  managedRefId: string | null;
  ruleConfig: unknown;
  hitCount: number;
  createdBy: null | { id: string; displayName: string };
  createdAt: string;
  updatedAt: string;
};

export type ExecutorIntelligenceItem = {
  id: string;
  title: string;
  slug: string;
  platform: string;
  extype: string | null;
  detected: boolean;
  updateStatus: boolean;
  version: string | null;
  updatedDateText: string | null;
  websiteHost: string | null;
  enabled: boolean;
  sourceName: string;
  generatedRuleIds: unknown;
  lastSeenAt: string;
  updatedAt: string;
};

export type ExecutorIntelligenceOverview = {
  settings: {
    id: string;
    enabled: boolean;
    sourceUrl: string;
    fallbackUrl: string;
    cacheTtlSeconds: number;
    attribution: string;
    lastSyncAt: string | null;
    lastSuccessAt: string | null;
    lastError: string | null;
    itemCount: number;
    windowsItemCount: number;
    generatedRuleCount: number;
    updatedById: string | null;
    createdAt: string;
    updatedAt: string;
  };
  counts: {
    items: number;
    windowsItems: number;
    generatedRules: number;
  };
  syncStatus?: "synced" | "cooldown";
  attribution: string;
  items: ExecutorIntelligenceItem[];
};

export type DetectionSample = {
  id: string;
  accountId: string | null;
  accountName: string | null;
  uploadedBy: null | { id: string; displayName: string };
  fileName: string;
  fileHash: string;
  sizeBytes: number;
  status: DetectionSampleStatus;
  stringCount: number;
  createdAt: string;
  deletedAt: string | null;
};

export type DetectionSampleString = {
  id: string;
  sampleId: string;
  valueHash: string;
  preview: string;
  length: number;
  selectedForRule: boolean;
  createdAt: string;
};

export type DetectionSampleStringsResponse = {
  sample: DetectionSample;
  strings: DetectionSampleString[];
};

export type ScanFindingsResponse = {
  items: ScanDetail["findings"];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
};

export type MonitoringOverview = {
  health: {
    api: "ok" | "error";
    database: "ok" | "error";
    n8n: "ok" | "error";
    ai: "ok" | "pending" | "error";
  };
  scannerUploads: {
    uploadsToday: number;
    failedUploadsToday: number;
    uploadAuthFailuresToday: number;
    uploadErrorRate: number;
  };
  scans: {
    completedToday: number;
    failedToday: number;
  };
  n8n: {
    latestEvent: null | {
      eventType: string;
      status: AutomationEventStatus;
      attemptCount: number;
      lastError: string | null;
      updatedAt: string;
    };
    failedEvents: number;
  };
  aiReviews: {
    pending: number;
    failed: number;
  };
  security: {
    highOrCriticalToday: number;
    bannedHwidMatchesToday: number;
  };
  alerts: {
    failed: number;
  };
};

export type SecurityEvent = {
  id: string;
  accountId: string | null;
  accountName: string | null;
  actorUserId: string | null;
  eventType: string;
  severity: MonitoringSeverity;
  sourceIp: string | null;
  message: string;
  metadata: unknown;
  createdAt: string;
};

export type AlertNotification = {
  id: string;
  securityEventId: string | null;
  channel: string;
  status: AlertNotificationStatus;
  severity: MonitoringSeverity;
  service: string;
  eventType: string;
  idempotencyKey: string;
  payloadRedacted: unknown;
  attemptCount: number;
  lastError: string | null;
  lastAttemptAt: string | null;
  createdAt: string;
  updatedAt: string;
};

export type RetentionSettings = {
  id: string;
  scanResultsDays: number;
  findingsEvidenceDays: number;
  screenshotsDays: number;
  detectionSamplesDays: number;
  monitoringEventsDays: number;
  securityEventsDays: number;
  auditLogsDays: number;
  updatedById: string | null;
  createdAt: string;
  updatedAt: string;
};

export type RetentionDryRun = {
  generatedAt: string;
  policy: RetentionSettings;
  candidates: {
    scanResults: number;
    scanFindings: number;
    scanEvidence: number;
    screenshots: number;
    detectionSamples: number;
    detectionSampleStrings: number;
    monitoringEvents: number;
    securityEvents: number;
    auditLogs: number;
  };
  deletesRecords: false;
};

export type PaginatedResponse<T> = {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
};

type ApiOptions = {
  cookieHeader?: string;
};

async function apiFetch(path: string, init?: RequestInit, options?: ApiOptions) {
  const headers = new Headers(init?.headers);

  if (options?.cookieHeader) {
    headers.set("cookie", options.cookieHeader);
  }

  const response = await fetch(`${env.NEXT_PUBLIC_API_URL}${path}`, {
    ...init,
    cache: init?.cache ?? "no-store",
    credentials: "include",
    headers
  });

  return response;
}

async function getApiErrorMessage(response: Response, fallback: string) {
  try {
    const payload = (await response.json()) as {
      message?: string | string[];
      error?: string;
    };
    if (Array.isArray(payload.message) && payload.message.length > 0) {
      return String(payload.message[0]);
    }
    if (typeof payload.message === "string" && payload.message.trim() !== "") {
      return payload.message;
    }
    if (typeof payload.error === "string" && payload.error.trim() !== "") {
      return payload.error;
    }
  } catch {
    // Keep the fallback for non-JSON error responses.
  }

  return fallback;
}

export async function getHealth(): Promise<HealthResponse> {
  const response = await fetch(`${env.NEXT_PUBLIC_API_URL}/health`, {
    cache: "no-store"
  });

  if (!response.ok) {
    throw new Error(`Health check failed with status ${response.status}`);
  }

  return (await response.json()) as HealthResponse;
}

export async function getMe(cookieHeader?: string): Promise<AuthResponse> {
  const response = await apiFetch("/auth/me", undefined, { cookieHeader });

  if (!response.ok) {
    throw new Error(`Session check failed with status ${response.status}`);
  }

  return (await response.json()) as AuthResponse;
}

export async function login(
  identifier: string,
  password: string
): Promise<AuthResponse> {
  const response = await fetch(`${env.NEXT_PUBLIC_API_URL}/auth/login`, {
    body: JSON.stringify({ identifier, password }),
    credentials: "include",
    headers: {
      "content-type": "application/json"
    },
    method: "POST"
  });

  if (!response.ok) {
    throw new Error("Invalid credentials");
  }

  return (await response.json()) as AuthResponse;
}

export async function logout(): Promise<void> {
  const response = await apiFetch("/auth/logout", { method: "POST" });

  if (!response.ok) {
    throw new Error(`Logout failed with status ${response.status}`);
  }
}

export async function getAccounts(
  cookieHeader?: string
): Promise<AccountListItem[]> {
  const response = await apiFetch("/accounts", undefined, { cookieHeader });

  if (!response.ok) {
    throw new Error(`Accounts request failed with status ${response.status}`);
  }

  return (await response.json()) as AccountListItem[];
}

export async function getAccount(
  accountId: string,
  cookieHeader?: string
): Promise<AccountDetail> {
  const response = await apiFetch(`/accounts/${accountId}`, undefined, {
    cookieHeader
  });

  if (!response.ok) {
    throw new Error(`Account request failed with status ${response.status}`);
  }

  return (await response.json()) as AccountDetail;
}

export async function getUsers(cookieHeader?: string): Promise<SafeUser[]> {
  const response = await apiFetch("/users", undefined, { cookieHeader });

  if (!response.ok) {
    throw new Error(`Users request failed with status ${response.status}`);
  }

  return (await response.json()) as SafeUser[];
}

export async function createAccount(payload: {
  name: string;
  slug?: string;
}): Promise<AccountListItem> {
  const response = await apiFetch("/accounts", {
    body: JSON.stringify(payload),
    headers: { "content-type": "application/json" },
    method: "POST"
  });

  if (!response.ok) {
    throw new Error("Could not create account");
  }

  return (await response.json()) as AccountListItem;
}

export async function updateAccount(
  accountId: string,
  payload: { name?: string; slug?: string; status?: AccountStatus }
): Promise<AccountListItem> {
  const response = await apiFetch(`/accounts/${accountId}`, {
    body: JSON.stringify(payload),
    headers: { "content-type": "application/json" },
    method: "PATCH"
  });

  if (!response.ok) {
    throw new Error("Could not update account");
  }

  return (await response.json()) as AccountListItem;
}

export async function suspendAccount(
  accountId: string
): Promise<AccountListItem> {
  const response = await apiFetch(`/accounts/${accountId}/suspend`, {
    method: "POST"
  });

  if (!response.ok) {
    throw new Error("Could not suspend account");
  }

  return (await response.json()) as AccountListItem;
}

export async function createUser(payload: {
  email: string;
  username: string;
  displayName: string;
  password: string;
  globalRole?: "SUPER_ADMIN" | "USER";
  status?: "ACTIVE" | "DISABLED";
}): Promise<SafeUser> {
  const response = await apiFetch("/users", {
    body: JSON.stringify(payload),
    headers: { "content-type": "application/json" },
    method: "POST"
  });

  if (!response.ok) {
    throw new Error(await getApiErrorMessage(response, "Could not create user"));
  }

  return (await response.json()) as SafeUser;
}

export async function updateUser(
  userId: string,
  payload: {
    displayName?: string;
    email?: string;
    globalRole?: "SUPER_ADMIN" | "USER";
    password?: string;
    status?: "ACTIVE" | "DISABLED";
    username?: string;
  }
): Promise<SafeUser> {
  const response = await apiFetch(`/users/${userId}`, {
    body: JSON.stringify(payload),
    headers: { "content-type": "application/json" },
    method: "PATCH"
  });

  if (!response.ok) {
    throw new Error(await getApiErrorMessage(response, "Could not update user"));
  }

  return (await response.json()) as SafeUser;
}

export async function disableUser(userId: string): Promise<SafeUser> {
  const response = await apiFetch(`/users/${userId}/disable`, {
    method: "POST"
  });

  if (!response.ok) {
    throw new Error(await getApiErrorMessage(response, "Could not disable user"));
  }

  return (await response.json()) as SafeUser;
}

export async function enableUser(userId: string): Promise<SafeUser> {
  return updateUser(userId, { status: "ACTIVE" });
}

export async function assignUserToAccount(
  accountId: string,
  payload: { userId: string; role: AccountRole }
): Promise<AccountDetail> {
  const response = await apiFetch(`/accounts/${accountId}/users`, {
    body: JSON.stringify(payload),
    headers: { "content-type": "application/json" },
    method: "POST"
  });

  if (!response.ok) {
    throw new Error("Could not assign user");
  }

  return (await response.json()) as AccountDetail;
}

export async function getScannerKeys(
  cookieHeader?: string
): Promise<ScannerKeyListItem[]> {
  const response = await apiFetch("/scanner-keys", undefined, {
    cookieHeader
  });

  if (!response.ok) {
    throw new Error(
      `Scanner keys request failed with status ${response.status}`
    );
  }

  return (await response.json()) as ScannerKeyListItem[];
}

export async function createScannerKey(
  accountId: string,
  payload: {
    name: string;
    expiresAt?: string | null;
    rateLimitPerHour?: number;
    allowedScannerVersions?: string[];
  }
): Promise<ScannerKeyRevealResponse> {
  const response = await apiFetch(`/accounts/${accountId}/scanner-keys`, {
    body: JSON.stringify(payload),
    headers: { "content-type": "application/json" },
    method: "POST"
  });

  if (!response.ok) {
    throw new Error("Could not create scanner key");
  }

  return (await response.json()) as ScannerKeyRevealResponse;
}

export async function rotateScannerKey(
  scannerKeyId: string
): Promise<ScannerKeyRevealResponse> {
  const response = await apiFetch(`/scanner-keys/${scannerKeyId}/rotate`, {
    method: "POST"
  });

  if (!response.ok) {
    throw new Error("Could not rotate scanner key");
  }

  return (await response.json()) as ScannerKeyRevealResponse;
}

export async function revokeScannerKey(
  scannerKeyId: string
): Promise<ScannerKeyListItem> {
  const response = await apiFetch(`/scanner-keys/${scannerKeyId}/revoke`, {
    method: "POST"
  });

  if (!response.ok) {
    throw new Error("Could not revoke scanner key");
  }

  return (await response.json()) as ScannerKeyListItem;
}

export async function getScans(cookieHeader?: string): Promise<ScanListItem[]> {
  const response = await apiFetch("/scans", undefined, { cookieHeader });

  if (!response.ok) {
    throw new Error(`Scans request failed with status ${response.status}`);
  }

  return (await response.json()) as ScanListItem[];
}

export async function getScan(
  scanId: string,
  cookieHeader?: string
): Promise<ScanDetail> {
  const response = await apiFetch(`/scans/${scanId}`, undefined, {
    cookieHeader
  });

  if (!response.ok) {
    throw new Error(`Scan request failed with status ${response.status}`);
  }

  return (await response.json()) as ScanDetail;
}

export async function retryAiReview(
  scanId: string
): Promise<{ status: "queued"; scanSessionId: string }> {
  const response = await apiFetch(`/scans/${scanId}/ai-review/retry`, {
    method: "POST"
  });

  if (!response.ok) {
    throw new Error("Could not retry AI review");
  }

  return (await response.json()) as {
    status: "queued";
    scanSessionId: string;
  };
}

export async function getDevices(
  cookieHeader?: string
): Promise<DeviceListItem[]> {
  const response = await apiFetch("/devices", undefined, { cookieHeader });

  if (!response.ok) {
    throw new Error(`Devices request failed with status ${response.status}`);
  }

  return (await response.json()) as DeviceListItem[];
}

export async function getDevice(
  deviceId: string,
  cookieHeader?: string
): Promise<DeviceDetail> {
  const response = await apiFetch(`/devices/${deviceId}`, undefined, {
    cookieHeader
  });

  if (!response.ok) {
    throw new Error(`Device request failed with status ${response.status}`);
  }

  return (await response.json()) as DeviceDetail;
}

export async function createDeviceMark(
  deviceId: string,
  payload: {
    status: DeviceMarkStatus;
    scope: DeviceMarkScope;
    accountId?: string;
    reason: string;
    expiresAt?: string | null;
    evidenceScanSessionId?: string;
    evidenceFindingId?: string;
    note?: string;
  }
): Promise<DeviceMark> {
  const response = await apiFetch(`/devices/${deviceId}/marks`, {
    body: JSON.stringify(payload),
    headers: { "content-type": "application/json" },
    method: "POST"
  });

  if (!response.ok) {
    throw new Error("Could not create device mark");
  }

  return (await response.json()) as DeviceMark;
}

export async function revokeDeviceMark(
  markId: string,
  reason: string
): Promise<DeviceMark> {
  const response = await apiFetch(`/device-marks/${markId}/revoke`, {
    body: JSON.stringify({ reason }),
    headers: { "content-type": "application/json" },
    method: "POST"
  });

  if (!response.ok) {
    throw new Error("Could not revoke device mark");
  }

  return (await response.json()) as DeviceMark;
}

export async function getDetectionRules(
  cookieHeader?: string
): Promise<DetectionRule[]> {
  const response = await apiFetch("/detection-rules", undefined, {
    cookieHeader
  });

  if (!response.ok) {
    throw new Error(`Detection rules request failed with status ${response.status}`);
  }

  return (await response.json()) as DetectionRule[];
}

export async function createDetectionRule(payload: {
  accountId?: string;
  scope: DetectionRuleScope;
  name: string;
  type: DetectionRuleType;
  category?: FindingCategory;
  severity?: Severity;
  enabled?: boolean;
  ruleConfig: unknown;
}): Promise<DetectionRule> {
  const response = await apiFetch("/detection-rules", {
    body: JSON.stringify(payload),
    headers: { "content-type": "application/json" },
    method: "POST"
  });

  if (!response.ok) {
    throw new Error("Could not create detection rule");
  }

  return (await response.json()) as DetectionRule;
}

export async function disableDetectionRule(ruleId: string): Promise<DetectionRule> {
  const response = await apiFetch(`/detection-rules/${ruleId}/disable`, {
    method: "POST"
  });

  if (!response.ok) {
    throw new Error("Could not disable detection rule");
  }

  return (await response.json()) as DetectionRule;
}

export async function getExecutorIntelligence(
  cookieHeader?: string
): Promise<ExecutorIntelligenceOverview> {
  const response = await apiFetch("/executor-intelligence", undefined, {
    cookieHeader
  });

  if (!response.ok) {
    throw new Error(`Executor intelligence request failed with status ${response.status}`);
  }

  return (await response.json()) as ExecutorIntelligenceOverview;
}

export async function syncExecutorIntelligence(): Promise<ExecutorIntelligenceOverview> {
  const response = await apiFetch("/executor-intelligence/sync", {
    method: "POST"
  });

  if (!response.ok) {
    throw new Error(await getApiErrorMessage(response, "Could not sync executor intelligence"));
  }

  return (await response.json()) as ExecutorIntelligenceOverview;
}

export async function updateExecutorIntelligenceSettings(payload: {
  enabled?: boolean;
  sourceUrl?: string;
  fallbackUrl?: string;
  cacheTtlSeconds?: number;
}): Promise<ExecutorIntelligenceOverview> {
  const response = await apiFetch("/executor-intelligence/settings", {
    body: JSON.stringify(payload),
    headers: { "content-type": "application/json" },
    method: "PATCH"
  });

  if (!response.ok) {
    throw new Error(await getApiErrorMessage(response, "Could not update executor intelligence"));
  }

  return (await response.json()) as ExecutorIntelligenceOverview;
}

export async function uploadDetectionSample(payload: {
  accountId?: string;
  fileName: string;
  contentBase64: string;
}): Promise<DetectionSample> {
  const response = await apiFetch("/detection-samples/upload", {
    body: JSON.stringify(payload),
    headers: { "content-type": "application/json" },
    method: "POST"
  });

  if (!response.ok) {
    throw new Error("Could not upload detection sample");
  }

  return (await response.json()) as DetectionSample;
}

export async function getDetectionSampleStrings(
  sampleId: string
): Promise<DetectionSampleStringsResponse> {
  const response = await apiFetch(`/detection-samples/${sampleId}/strings`);

  if (!response.ok) {
    throw new Error("Could not load sample strings");
  }

  return (await response.json()) as DetectionSampleStringsResponse;
}

export async function getScanFindings(
  scanId: string,
  query: {
    q?: string;
    severity?: Severity;
    category?: FindingCategory;
    page?: number;
    pageSize?: number;
    sort?: "createdAt" | "severity" | "category" | "title" | "confidence";
    direction?: "asc" | "desc";
  } = {},
  cookieHeader?: string
): Promise<ScanFindingsResponse> {
  const search = new URLSearchParams();

  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== "") {
      search.set(key, String(value));
    }
  }

  const suffix = search.size > 0 ? `?${search.toString()}` : "";
  const response = await apiFetch(`/scans/${scanId}/findings${suffix}`, undefined, {
    cookieHeader
  });

  if (!response.ok) {
    throw new Error(`Scan findings request failed with status ${response.status}`);
  }

  return (await response.json()) as ScanFindingsResponse;
}

function queryString(query: Record<string, string | number | undefined>) {
  const search = new URLSearchParams();

  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== "") {
      search.set(key, String(value));
    }
  }

  return search.size > 0 ? `?${search.toString()}` : "";
}

export async function getMonitoringOverview(
  cookieHeader?: string
): Promise<MonitoringOverview> {
  const response = await apiFetch("/monitoring/overview", undefined, {
    cookieHeader
  });

  if (!response.ok) {
    throw new Error(`Monitoring overview failed with status ${response.status}`);
  }

  return (await response.json()) as MonitoringOverview;
}

export async function getSecurityEvents(
  query: {
    eventType?: string;
    page?: number;
    pageSize?: number;
    q?: string;
    severity?: MonitoringSeverity;
  } = {},
  cookieHeader?: string
): Promise<PaginatedResponse<SecurityEvent>> {
  const response = await apiFetch(
    `/monitoring/security-events${queryString(query)}`,
    undefined,
    { cookieHeader }
  );

  if (!response.ok) {
    throw new Error(`Security events failed with status ${response.status}`);
  }

  return (await response.json()) as PaginatedResponse<SecurityEvent>;
}

export async function getAlertNotifications(
  query: {
    eventType?: string;
    page?: number;
    pageSize?: number;
    q?: string;
    severity?: MonitoringSeverity;
    status?: AlertNotificationStatus;
  } = {},
  cookieHeader?: string
): Promise<PaginatedResponse<AlertNotification>> {
  const response = await apiFetch(
    `/monitoring/alerts${queryString(query)}`,
    undefined,
    { cookieHeader }
  );

  if (!response.ok) {
    throw new Error(`Alert history failed with status ${response.status}`);
  }

  return (await response.json()) as PaginatedResponse<AlertNotification>;
}

export async function retryAlertNotification(
  alertId: string
): Promise<{ status: AlertNotificationStatus; alertId: string; attemptCount: number }> {
  const response = await apiFetch(`/monitoring/alerts/${alertId}/retry`, {
    method: "POST"
  });

  if (!response.ok) {
    throw new Error("Could not retry alert notification");
  }

  return (await response.json()) as {
    status: AlertNotificationStatus;
    alertId: string;
    attemptCount: number;
  };
}

export async function getRetentionSettings(
  cookieHeader?: string
): Promise<RetentionSettings> {
  const response = await apiFetch("/settings/retention", undefined, {
    cookieHeader
  });

  if (!response.ok) {
    throw new Error(`Retention settings failed with status ${response.status}`);
  }

  return (await response.json()) as RetentionSettings;
}

export async function updateRetentionSettings(
  payload: Partial<
    Pick<
      RetentionSettings,
      | "scanResultsDays"
      | "findingsEvidenceDays"
      | "screenshotsDays"
      | "detectionSamplesDays"
      | "monitoringEventsDays"
      | "securityEventsDays"
      | "auditLogsDays"
    >
  >
): Promise<RetentionSettings> {
  const response = await apiFetch("/settings/retention", {
    body: JSON.stringify(payload),
    headers: { "content-type": "application/json" },
    method: "PATCH"
  });

  if (!response.ok) {
    throw new Error("Could not update retention settings");
  }

  return (await response.json()) as RetentionSettings;
}

export async function retentionDryRun(): Promise<RetentionDryRun> {
  const response = await apiFetch("/settings/retention/dry-run", {
    body: "{}",
    headers: { "content-type": "application/json" },
    method: "POST"
  });

  if (!response.ok) {
    throw new Error("Could not run retention dry run");
  }

  return (await response.json()) as RetentionDryRun;
}

export async function updateScanLabel(
  scanId: string,
  playerLabel: string | null
): Promise<ScanDetail> {
  const response = await apiFetch(`/scans/${scanId}`, {
    body: JSON.stringify({ playerLabel }),
    headers: { "content-type": "application/json" },
    method: "PATCH"
  });

  if (!response.ok) {
    throw new Error(await getApiErrorMessage(response, "Could not update scan label"));
  }

  return (await response.json()) as ScanDetail;
}

export function scanExportUrl(scanId: string, format: "html" | "json") {
  return `${env.NEXT_PUBLIC_API_URL}/scans/${scanId}/export?format=${format}`;
}
