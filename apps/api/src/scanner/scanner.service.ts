import {
  BadRequestException,
  Injectable,
  UnauthorizedException
} from "@nestjs/common";
import {
  AccountStatus,
  DetectionRuleScope,
  DeviceMarkScope,
  DeviceMarkStatus,
  FingerprintConfidence,
  FindingCategory,
  MonitoringSeverity,
  Prisma,
  ScanSession,
  ScanStatus,
  ScannerKeyStatus,
  Severity
} from "@prisma/client";
import { createHash } from "node:crypto";
import {
  sanitizeForStorage,
  sanitizeJsonArray,
  sanitizeText
} from "../common/data-sanitizer";
import { env } from "../config/env";
import { MonitoringService } from "../monitoring/monitoring.service";
import { PrismaService } from "../prisma/prisma.service";
import { ScanReviewsService } from "../scan-reviews/scan-reviews.service";
import { getScannerKeyPrefix, hashScannerKey } from "../scanner-keys/scanner-key-crypto";
import {
  createNonce,
  createUploadToken,
  hashUploadSecret,
  safeHashEquals
} from "./scanner-token-crypto";

export type ValidateKeyInput = {
  scannerKey: string;
  scannerVersion: string;
  platform: string;
  arch: string;
  playerLabel?: string;
};

export type ScanResultInput = {
  uploadToken: string;
  nonce: string;
  accountId?: string;
  scannerVersion?: string;
  startedAt?: Date;
  finishedAt?: Date;
  overview?: unknown;
  systemIdentity?: unknown;
  networkSnapshot?: unknown;
  integrity?: unknown;
  modules?: IncomingModule[];
  evidence?: IncomingEvidence[];
  processTimeline?: unknown;
  exploreFiles?: unknown;
  utilities?: unknown;
  windowsItems?: unknown;
  auditLog?: unknown;
  deviceFingerprint?: IncomingDeviceFingerprint;
  device_fingerprint?: IncomingDeviceFingerprint;
  launcherProfiles?: IncomingLauncherProfile[];
  clientModAssets?: IncomingClientModAsset[];
  processTimes?: IncomingProcessTime[];
  fileLogs?: IncomingFileLog[];
  loadedModules?: unknown;
  processHandles?: unknown;
  services?: unknown;
  drivers?: unknown;
  persistenceItems?: unknown;
  eventLogs?: unknown;
  defenderEvents?: unknown;
  executionArtifacts?: unknown;
  fileTriage?: unknown;
  networkConnections?: unknown;
  dnsCache?: unknown;
  hostsEntries?: unknown;
  forensicTimeline?: unknown;
  findings?: IncomingFinding[];
  indicationLogs?: IncomingFinding[];
};

export type CompleteScanInput = {
  uploadToken: string;
  nonce: string;
  status?: "COMPLETED" | "FAILED" | "PARTIAL";
  telemetry?: {
    uploadDurationMs?: number;
    uploadAttemptCount?: number;
    completeAttemptCount?: number;
    lastErrorCode?: string;
    scannerVersion?: string;
  };
};

type IncomingFinding = {
  category?: FindingCategory;
  severity?: Severity;
  title: string;
  message: string;
  ruleId?: string;
  confidence?: number;
  sourceModule?: string;
  evidenceRef?: string;
  metadata?: unknown;
};

type IncomingModule = {
  moduleName: string;
  status: string;
  durationMs?: number;
  errorCode?: string;
  errorMessage?: string;
};

type IncomingEvidence = {
  clientEvidenceId?: string;
  type: string;
  title: string;
  data?: unknown;
  storageRef?: string;
};

type IncomingDeviceFingerprint = {
  hash: string;
  version: string;
  confidence: FingerprintConfidence;
};

type IncomingLauncherProfile = {
  profileName: string;
  launcherType: string;
  version?: string;
  channel?: string;
  path?: string;
  executableHash?: string;
  publisher?: string;
  status?: string;
  tags?: unknown[];
  installTime?: Date;
  updateTime?: Date;
  lastLaunchTime?: Date;
  metadata?: unknown;
};

type IncomingClientModAsset = {
  name: string;
  sourceLauncher?: string;
  path?: string;
  fileCount?: number;
  totalSize?: number;
  createdTime?: Date;
  modifiedTime?: Date;
  status?: string;
  metadata?: unknown;
};

type IncomingProcessTime = {
  processName: string;
  path?: string;
  firstSeenAt?: Date;
  lastSeenAt?: Date;
  startedAt?: Date;
  endedAt?: Date;
  durationMs?: number;
  source?: string;
  status?: string;
  metadata?: unknown;
};

type IncomingFileLog = {
  action: string;
  path?: string;
  oldPath?: string;
  newPath?: string;
  timestamp?: Date;
  source?: string;
  confidence?: number;
  relatedProcess?: string;
  severity?: Severity;
  metadata?: unknown;
};

type ChunkedResultSection =
  | "processTimeline"
  | "exploreFiles"
  | "utilities"
  | "windowsItems"
  | "launcherProfiles"
  | "clientModAssets"
  | "processTimes"
  | "fileLogs"
  | "loadedModules"
  | "processHandles"
  | "services"
  | "drivers"
  | "persistenceItems"
  | "eventLogs"
  | "defenderEvents"
  | "executionArtifacts"
  | "fileTriage"
  | "networkConnections"
  | "dnsCache"
  | "hostsEntries"
  | "forensicTimeline";

type SectionUploadInput = {
  uploadToken: string;
  nonce: string;
  section: ChunkedResultSection;
  items?: unknown[];
  data?: unknown;
  totalItems?: number;
  chunkIndex: number;
  chunkCount: number;
  payloadHash?: string;
  status: "uploaded" | "failed";
  errorCode?: string;
};

const jsonResultSections = new Set<ChunkedResultSection>([
  "processTimeline",
  "exploreFiles",
  "utilities",
  "windowsItems",
  "loadedModules",
  "processHandles",
  "services",
  "drivers",
  "persistenceItems",
  "eventLogs",
  "defenderEvents",
  "executionArtifacts",
  "fileTriage",
  "networkConnections",
  "dnsCache",
  "hostsEntries",
  "forensicTimeline"
]);

const enabledModules = [
  "overview",
  "process_timeline",
  "utilities",
  "windows_items",
  "explorer",
  "roblox_launcher_profiles",
  "roblox_client_mod_assets",
  "roblox_process_times",
  "roblox_file_logs"
];

function optionalText(value: string | undefined) {
  return value ? sanitizeText(value.trim()) : null;
}

function optionalStatus(value: string | undefined) {
  return value?.trim().toLowerCase() || "normal";
}

function optionalBigInt(value: number | undefined) {
  return value === undefined ? null : BigInt(Math.trunc(value));
}

function getDeviceFingerprintPrefix(hash: string) {
  const compact = hash.replace(/[^A-Za-z0-9]/g, "").slice(0, 8).toUpperCase();

  return `dfp_${compact || "UNKNOWN"}`;
}

function normalizeFingerprintConfidence(
  value: FingerprintConfidence | undefined
) {
  return value ?? FingerprintConfidence.MEDIUM;
}

function payloadHash(value: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(value), "utf8")
    .digest("hex");
}

function plainObject(value: unknown): Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function jsonArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function stringField(
  value: unknown,
  fallback: string,
  maxLength: number
): string {
  return sanitizeText(typeof value === "string" ? value.trim() : fallback).slice(
    0,
    maxLength
  );
}

function dateFromUnknown(value: unknown): Date | undefined {
  if (value instanceof Date) {
    return value;
  }
  if (typeof value !== "string" || value.trim() === "") {
    return undefined;
  }
  const date = new Date(value);

  return Number.isNaN(date.getTime()) ? undefined : date;
}

function maxSeverity(findings: Array<{ severity: Severity }>): Severity {
  const rank = {
    [Severity.INFO]: 0,
    [Severity.CLEAN]: 0,
    [Severity.WARNING]: 25,
    [Severity.SEVERE]: 75,
    [Severity.CRITICAL]: 100
  };
  let current: Severity = Severity.CLEAN;

  for (const finding of findings) {
    if (rank[finding.severity] > rank[current]) {
      current = finding.severity;
    }
  }

  return current;
}

function riskScoreFor(
  findings: Array<{
    severity: Severity;
    sourceModule?: string | null;
    confidence?: number | null;
    ruleId?: string | null;
    category?: FindingCategory | null;
  }>
): number {
  const weights = {
    [Severity.INFO]: 0,
    [Severity.CLEAN]: 0,
    [Severity.WARNING]: 8,
    [Severity.SEVERE]: 30,
    [Severity.CRITICAL]: 60
  };
  const moduleWarningCap = 24;
  const moduleTotals = new Map<string, number>();
  let score = 0;

  for (const finding of findings) {
    const base = weights[finding.severity] ?? 0;
    if (base === 0) {
      continue;
    }
    if (finding.severity === Severity.WARNING) {
      const source = finding.sourceModule ?? "unknown";
      const current = moduleTotals.get(source) ?? 0;
      if (current >= moduleWarningCap && !finding.ruleId) {
        continue;
      }
      const remaining = finding.ruleId
        ? base
        : Math.min(base, moduleWarningCap - current);
      moduleTotals.set(source, current + remaining);
      score += remaining;
      continue;
    }
    score += base;
  }

  return Math.min(100, score);
}

function markSeverity(status: DeviceMarkStatus) {
  if (status === DeviceMarkStatus.BANNED) {
    return Severity.SEVERE;
  }

  if (status === DeviceMarkStatus.SUSPICIOUS) {
    return Severity.WARNING;
  }

  return Severity.INFO;
}

function markRank(status: DeviceMarkStatus) {
  return {
    [DeviceMarkStatus.BANNED]: 4,
    [DeviceMarkStatus.SUSPICIOUS]: 3,
    [DeviceMarkStatus.TRUSTED]: 2,
    [DeviceMarkStatus.CLEARED]: 1
  }[status];
}

@Injectable()
export class ScannerService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly scanReviews: ScanReviewsService,
    private readonly monitoring: MonitoringService
  ) {}

  async validateKey(input: ValidateKeyInput, sourceIp?: string) {
    const keyPrefix = getScannerKeyPrefix(input.scannerKey);
    const keyHash = hashScannerKey(input.scannerKey);
    const scannerKey = await this.prisma.scannerKey.findFirst({
      where: {
        keyPrefix,
        keyHash
      },
      include: {
        account: {
          select: {
            id: true,
            name: true,
            status: true,
            deletedAt: true
          }
        }
      }
    });

    if (!scannerKey) {
      await this.monitoring.recordSecurityEvent({
        eventType: "INVALID_SCANNER_KEY",
        message: "Invalid scanner key validation attempt.",
        metadata: { keyPrefix },
        severity: MonitoringSeverity.WARNING,
        sourceIp
      });

      return this.invalid("INVALID_KEY", "Scanner key is invalid.");
    }

    if (
      scannerKey.account.deletedAt ||
      scannerKey.account.status !== AccountStatus.ACTIVE
    ) {
      await this.monitoring.recordSecurityEvent({
        accountId: scannerKey.accountId,
        eventType: "ACCOUNT_DISABLED_KEY_USED",
        message: "Scanner key was used for a disabled account.",
        metadata: { keyPrefix: scannerKey.keyPrefix },
        severity: MonitoringSeverity.HIGH,
        sourceIp
      });

      return this.invalid("ACCOUNT_DISABLED", "Account is not active.");
    }

    if (scannerKey.status === ScannerKeyStatus.REVOKED) {
      await this.monitoring.recordSecurityEvent({
        accountId: scannerKey.accountId,
        eventType: "REVOKED_SCANNER_KEY_USED",
        message: "Revoked scanner key usage attempt.",
        metadata: { keyPrefix: scannerKey.keyPrefix },
        severity: MonitoringSeverity.HIGH,
        sourceIp
      });

      return this.invalid("KEY_REVOKED", "Scanner key is revoked.");
    }

    if (
      scannerKey.status === ScannerKeyStatus.EXPIRED ||
      (scannerKey.expiresAt && scannerKey.expiresAt <= new Date())
    ) {
      if (scannerKey.status !== ScannerKeyStatus.EXPIRED) {
        await this.prisma.scannerKey.update({
          where: { id: scannerKey.id },
          data: { status: ScannerKeyStatus.EXPIRED }
        });
      }

      await this.monitoring.recordSecurityEvent({
        accountId: scannerKey.accountId,
        eventType: "EXPIRED_SCANNER_KEY_USED",
        message: "Expired scanner key usage attempt.",
        metadata: { keyPrefix: scannerKey.keyPrefix },
        severity: MonitoringSeverity.WARNING,
        sourceIp
      });

      return this.invalid("KEY_EXPIRED", "Scanner key is expired.");
    }

    const allowedVersions = Array.isArray(scannerKey.allowedScannerVersions)
      ? scannerKey.allowedScannerVersions
      : [];

    if (
      allowedVersions.length > 0 &&
      !allowedVersions.includes(input.scannerVersion)
    ) {
      await this.monitoring.recordSecurityEvent({
        accountId: scannerKey.accountId,
        eventType: "SCANNER_VERSION_BLOCKED",
        message: "Scanner version was blocked by key version policy.",
        metadata: {
          keyPrefix: scannerKey.keyPrefix,
          scannerVersion: input.scannerVersion
        },
        severity: MonitoringSeverity.WARNING,
        sourceIp
      });

      return this.invalid(
        "VERSION_NOT_ALLOWED",
        "Scanner version is not allowed."
      );
    }

    const uploadToken = createUploadToken();
    const nonce = createNonce();
    const expiresAt = new Date(
      Date.now() + env.SCANNER_UPLOAD_TOKEN_TTL_SECONDS * 1000
    );

    const session = await this.prisma.$transaction(async (tx) => {
      await tx.scannerKey.update({
        where: { id: scannerKey.id },
        data: {
          lastUsedAt: new Date(),
          usageCount: { increment: 1 }
        }
      });

      return tx.scanSession.create({
        data: {
          accountId: scannerKey.accountId,
          scannerKeyId: scannerKey.id,
          playerLabel: input.playerLabel?.trim() || null,
          scannerVersion: input.scannerVersion,
          platform: input.platform,
          arch: input.arch,
          uploadTokenHash: hashUploadSecret(uploadToken),
          nonceHash: hashUploadSecret(nonce),
          startedAt: new Date(),
          expiresAt,
          sourceIp
        }
      });
    });

    return {
      valid: true,
      accountId: scannerKey.account.id,
      accountName: scannerKey.account.name,
      scanSessionId: session.id,
      uploadToken,
      nonce,
      expiresAt,
      enabledModules,
      consentScope: {
        processList: true,
        fileMetadata: true,
        screenshot: false
      }
    };
  }

  async saveResults(
    scanSessionId: string,
    input: ScanResultInput,
    sourceIp?: string
  ) {
    const session = await this.getUploadSessionOrRecord(
      scanSessionId,
      input,
      sourceIp
    );
    const uploadedFindings = this.normalizeFindings([
      ...(input.findings ?? []),
      ...(input.indicationLogs ?? [])
    ]);
    let storedFindings = uploadedFindings.length;
    const deviceSecurityEvents: Array<{
      eventType: string;
      message: string;
      metadata: unknown;
      severity: MonitoringSeverity;
    }> = [];

    await this.prisma.$transaction(async (tx) => {
      const deviceMatchFindings = await this.applyDeviceFingerprint(
        tx,
        session,
        input.deviceFingerprint ?? input.device_fingerprint
      );
      deviceSecurityEvents.push(
        ...deviceMatchFindings.map((finding) => ({
          eventType:
            finding.title === "Banned HWID match"
              ? "BANNED_HWID_MATCH"
              : "SUSPICIOUS_HWID_MATCH",
          message: finding.message,
          metadata: finding.metadata,
          severity:
            finding.title === "Banned HWID match"
              ? MonitoringSeverity.HIGH
              : MonitoringSeverity.WARNING
        }))
      );
      const findings = [...uploadedFindings, ...deviceMatchFindings];
      const submittedRuleIds = Array.from(
        new Set(
          findings
            .map((finding) => finding.ruleId)
            .filter((ruleId): ruleId is string => Boolean(ruleId))
        )
      );
      const existingRuleIds = new Set(
        (
          await tx.scanFinding.findMany({
            where: { scanSessionId, ruleId: { not: null } },
            select: { ruleId: true }
          })
        )
          .map((finding) => finding.ruleId)
          .filter((ruleId): ruleId is string => Boolean(ruleId))
      );
      const validRuleIds = new Set(
        submittedRuleIds.length > 0
          ? (
              await tx.detectionRule.findMany({
                where: {
                  id: { in: submittedRuleIds },
                  enabled: true,
                  deletedAt: null,
                  OR: [
                    { scope: DetectionRuleScope.GLOBAL, accountId: null },
                    {
                      scope: DetectionRuleScope.ACCOUNT,
                      accountId: session.accountId
                    }
                  ]
                },
                select: { id: true }
              })
            ).map((rule) => rule.id)
          : []
      );
      const riskScore = riskScoreFor(findings);
      const maxSeverityValue = maxSeverity(findings);
      const normalizedPayload = {
        scanSessionId,
        overview: sanitizeForStorage(input.overview),
        systemIdentity: sanitizeForStorage(input.systemIdentity),
        networkSnapshot: sanitizeForStorage(input.networkSnapshot),
        integrity: sanitizeForStorage(input.integrity),
        processTimeline: sanitizeJsonArray(input.processTimeline),
        exploreFiles: sanitizeJsonArray(input.exploreFiles),
        utilities: sanitizeJsonArray(input.utilities),
        windowsItems: sanitizeJsonArray(input.windowsItems),
        auditLog: sanitizeJsonArray(input.auditLog),
        deviceFingerprint: input.deviceFingerprint
          ? {
              prefix: getDeviceFingerprintPrefix(input.deviceFingerprint.hash),
              version: input.deviceFingerprint.version,
              confidence: input.deviceFingerprint.confidence
            }
          : undefined,
        launcherProfiles: (input.launcherProfiles ?? []).map((item) =>
          sanitizeForStorage(item)
        ),
        clientModAssets: (input.clientModAssets ?? []).map((item) =>
          sanitizeForStorage(item)
        ),
        processTimes: (input.processTimes ?? []).map((item) =>
          sanitizeForStorage(item)
        ),
        fileLogs: (input.fileLogs ?? []).map((item) =>
          sanitizeForStorage(item)
        ),
        loadedModules: sanitizeJsonArray(input.loadedModules),
        processHandles: sanitizeJsonArray(input.processHandles),
        services: sanitizeJsonArray(input.services),
        drivers: sanitizeJsonArray(input.drivers),
        persistenceItems: sanitizeJsonArray(input.persistenceItems),
        eventLogs: sanitizeJsonArray(input.eventLogs),
        defenderEvents: sanitizeJsonArray(input.defenderEvents),
        executionArtifacts: sanitizeJsonArray(input.executionArtifacts),
        fileTriage: sanitizeJsonArray(input.fileTriage),
        networkConnections: sanitizeJsonArray(input.networkConnections),
        dnsCache: sanitizeJsonArray(input.dnsCache),
        hostsEntries: sanitizeJsonArray(input.hostsEntries),
        forensicTimeline: sanitizeJsonArray(input.forensicTimeline),
        modules: input.modules ?? [],
        evidence: (input.evidence ?? []).map((item) => ({
          ...item,
          data: sanitizeForStorage(item.data)
        })),
        findings
      };
      storedFindings = findings.length;

      await tx.scanResult.upsert({
        where: { scanSessionId },
        create: {
          scanSessionId,
          accountId: session.accountId,
          payloadHash: payloadHash(normalizedPayload),
          overview: sanitizeForStorage(input.overview),
          systemIdentity: sanitizeForStorage(input.systemIdentity),
          networkSnapshot: sanitizeForStorage(input.networkSnapshot),
          integrity: sanitizeForStorage(input.integrity),
          processTimeline: sanitizeJsonArray(input.processTimeline),
          exploreFiles: sanitizeJsonArray(input.exploreFiles),
          utilities: sanitizeJsonArray(input.utilities),
          windowsItems: sanitizeJsonArray(input.windowsItems),
          auditLog: sanitizeJsonArray(input.auditLog),
          loadedModules: sanitizeJsonArray(input.loadedModules),
          processHandles: sanitizeJsonArray(input.processHandles),
          services: sanitizeJsonArray(input.services),
          drivers: sanitizeJsonArray(input.drivers),
          persistenceItems: sanitizeJsonArray(input.persistenceItems),
          eventLogs: sanitizeJsonArray(input.eventLogs),
          defenderEvents: sanitizeJsonArray(input.defenderEvents),
          executionArtifacts: sanitizeJsonArray(input.executionArtifacts),
          fileTriage: sanitizeJsonArray(input.fileTriage),
          networkConnections: sanitizeJsonArray(input.networkConnections),
          dnsCache: sanitizeJsonArray(input.dnsCache),
          hostsEntries: sanitizeJsonArray(input.hostsEntries),
          forensicTimeline: sanitizeJsonArray(input.forensicTimeline)
        },
        update: {
          payloadHash: payloadHash(normalizedPayload),
          overview: sanitizeForStorage(input.overview),
          systemIdentity: sanitizeForStorage(input.systemIdentity),
          networkSnapshot: sanitizeForStorage(input.networkSnapshot),
          integrity: sanitizeForStorage(input.integrity),
          processTimeline: sanitizeJsonArray(input.processTimeline),
          exploreFiles: sanitizeJsonArray(input.exploreFiles),
          utilities: sanitizeJsonArray(input.utilities),
          windowsItems: sanitizeJsonArray(input.windowsItems),
          auditLog: sanitizeJsonArray(input.auditLog),
          loadedModules: sanitizeJsonArray(input.loadedModules),
          processHandles: sanitizeJsonArray(input.processHandles),
          services: sanitizeJsonArray(input.services),
          drivers: sanitizeJsonArray(input.drivers),
          persistenceItems: sanitizeJsonArray(input.persistenceItems),
          eventLogs: sanitizeJsonArray(input.eventLogs),
          defenderEvents: sanitizeJsonArray(input.defenderEvents),
          executionArtifacts: sanitizeJsonArray(input.executionArtifacts),
          fileTriage: sanitizeJsonArray(input.fileTriage),
          networkConnections: sanitizeJsonArray(input.networkConnections),
          dnsCache: sanitizeJsonArray(input.dnsCache),
          hostsEntries: sanitizeJsonArray(input.hostsEntries),
          forensicTimeline: sanitizeJsonArray(input.forensicTimeline)
        }
      });

      await tx.scanFinding.deleteMany({
        where: { scanSessionId }
      });

      await tx.scanModule.deleteMany({
        where: { scanSessionId }
      });

      await tx.scanEvidence.deleteMany({
        where: { scanSessionId }
      });

      await tx.launcherProfile.deleteMany({
        where: { scanSessionId }
      });

      await tx.clientModAsset.deleteMany({
        where: { scanSessionId }
      });

      await tx.processTime.deleteMany({
        where: { scanSessionId }
      });

      await tx.fileLog.deleteMany({
        where: { scanSessionId }
      });

      if (input.modules && input.modules.length > 0) {
        await tx.scanModule.createMany({
          data: input.modules.map((module) => ({
            scanSessionId,
            accountId: session.accountId,
            moduleName: module.moduleName.trim(),
            status: module.status.trim().toLowerCase(),
            durationMs: module.durationMs,
            errorCode: module.errorCode?.trim() || null,
            errorMessage: module.errorMessage
              ? sanitizeText(module.errorMessage)
              : null
          }))
        });
      }

      const evidenceByClientId = new Map<string, string>();

      for (const evidence of input.evidence ?? []) {
        const created = await tx.scanEvidence.create({
          data: {
            scanSessionId,
            accountId: session.accountId,
            clientEvidenceId: evidence.clientEvidenceId?.trim() || null,
            type: evidence.type.trim().toLowerCase(),
            title: sanitizeText(evidence.title.trim()),
            data: sanitizeForStorage(evidence.data),
            storageRef: evidence.storageRef
              ? sanitizeText(evidence.storageRef)
              : null
          }
        });

        if (created.clientEvidenceId) {
          evidenceByClientId.set(created.clientEvidenceId, created.id);
        }
      }

      if (input.launcherProfiles && input.launcherProfiles.length > 0) {
        await tx.launcherProfile.createMany({
          data: input.launcherProfiles.map((profile) => ({
            scanSessionId,
            accountId: session.accountId,
            profileName: sanitizeText(profile.profileName.trim()),
            launcherType: sanitizeText(profile.launcherType.trim()),
            version: optionalText(profile.version),
            channel: optionalText(profile.channel),
            pathMasked: optionalText(profile.path),
            executableHash: optionalText(profile.executableHash),
            publisher: optionalText(profile.publisher),
            status: optionalStatus(profile.status),
            tags: sanitizeJsonArray(profile.tags ?? []),
            installTime: profile.installTime,
            updateTime: profile.updateTime,
            lastLaunchTime: profile.lastLaunchTime,
            metadata: sanitizeForStorage(profile.metadata)
          }))
        });
      }

      if (input.clientModAssets && input.clientModAssets.length > 0) {
        await tx.clientModAsset.createMany({
          data: input.clientModAssets.map((asset) => ({
            scanSessionId,
            accountId: session.accountId,
            name: sanitizeText(asset.name.trim()),
            sourceLauncher: optionalText(asset.sourceLauncher),
            pathMasked: optionalText(asset.path),
            fileCount: asset.fileCount,
            totalSize: optionalBigInt(asset.totalSize),
            createdTime: asset.createdTime,
            modifiedTime: asset.modifiedTime,
            status: optionalStatus(asset.status),
            metadata: sanitizeForStorage(asset.metadata)
          }))
        });
      }

      if (input.processTimes && input.processTimes.length > 0) {
        await tx.processTime.createMany({
          data: input.processTimes.map((processTime) => ({
            scanSessionId,
            accountId: session.accountId,
            processName: sanitizeText(processTime.processName.trim()),
            pathMasked: optionalText(processTime.path),
            firstSeenAt: processTime.firstSeenAt,
            lastSeenAt: processTime.lastSeenAt,
            startedAt: processTime.startedAt,
            endedAt: processTime.endedAt,
            durationMs: processTime.durationMs,
            source: optionalText(processTime.source),
            status: optionalStatus(processTime.status),
            metadata: sanitizeForStorage(processTime.metadata)
          }))
        });
      }

      if (input.fileLogs && input.fileLogs.length > 0) {
        await tx.fileLog.createMany({
          data: input.fileLogs.map((fileLog) => ({
            scanSessionId,
            accountId: session.accountId,
            action: sanitizeText(fileLog.action.trim()).toLowerCase(),
            pathMasked: optionalText(fileLog.path),
            oldPathMasked: optionalText(fileLog.oldPath),
            newPathMasked: optionalText(fileLog.newPath),
            timestamp: fileLog.timestamp,
            source: optionalText(fileLog.source),
            confidence: fileLog.confidence,
            relatedProcess: optionalText(fileLog.relatedProcess),
            severity: fileLog.severity ?? Severity.INFO,
            metadata: sanitizeForStorage(fileLog.metadata)
          }))
        });
      }

      if (findings.length > 0) {
        await tx.scanFinding.createMany({
          data: findings.map((finding) => ({
            scanSessionId,
            accountId: session.accountId,
            category: finding.category,
            severity: finding.severity,
            title: finding.title,
            message: finding.message,
            ruleId:
              finding.ruleId && validRuleIds.has(finding.ruleId)
                ? finding.ruleId
                : null,
            evidenceId: finding.evidenceRef
              ? (evidenceByClientId.get(finding.evidenceRef) ?? null)
              : null,
            confidence: finding.confidence,
            sourceModule: finding.sourceModule,
            metadata: finding.metadata
          }))
        });
      }

      const newRuleHitIds = submittedRuleIds.filter(
        (ruleId) => validRuleIds.has(ruleId) && !existingRuleIds.has(ruleId)
      );

      if (newRuleHitIds.length > 0) {
        await tx.detectionRule.updateMany({
          where: { id: { in: newRuleHitIds } },
          data: { hitCount: { increment: 1 } }
        });
      }

      await tx.scanSession.update({
        where: { id: scanSessionId },
        data: {
          status: ScanStatus.UPLOADING,
          riskScore,
          maxSeverity: maxSeverityValue
        }
      });
    });

    for (const event of deviceSecurityEvents) {
      await this.monitoring.recordSecurityEvent({
        accountId: session.accountId,
        eventType: event.eventType,
        message: event.message,
        metadata: { scanSessionId, match: event.metadata },
        severity: event.severity,
        sourceIp
      });
    }

    return {
      status: "ok",
      scanSessionId,
      storedFindings
    };
  }

  async saveResultsCore(
    scanSessionId: string,
    input: ScanResultInput,
    sourceIp?: string
  ) {
    const integrity = {
      ...plainObject(input.integrity),
      uploadMode: "chunked",
      sectionUploadStatus:
        plainObject(input.integrity).sectionUploadStatus ?? {}
    };

    return this.saveResults(
      scanSessionId,
      {
        ...input,
        integrity
      },
      sourceIp
    );
  }

  async saveResultsSection(
    scanSessionId: string,
    input: SectionUploadInput,
    sourceIp?: string
  ) {
    const session = await this.getUploadSessionOrRecord(
      scanSessionId,
      input,
      sourceIp
    );
    const rawItems =
      input.items ??
      (Array.isArray(input.data)
        ? input.data
        : input.data === undefined
          ? []
          : [input.data]);
    const sanitizedItems: unknown[] = rawItems.map((item) =>
      sanitizeForStorage(item)
    );
    const itemCount = rawItems.length;
    let uploadedItems = input.status === "failed" ? 0 : itemCount;

    await this.prisma.$transaction(async (tx) => {
      const current = await tx.scanResult.findUnique({
        where: { scanSessionId }
      });

      if (!current) {
        throw new BadRequestException("Upload core result before sections");
      }

      const integrity = plainObject(current.integrity);
      const sectionUploadStatus = plainObject(
        integrity.sectionUploadStatus
      );
      const sectionUploadChunks = plainObject(
        integrity.sectionUploadChunks
      );
      const sectionChunks = plainObject(
        sectionUploadChunks[input.section]
      );
      const chunkKey = String(input.chunkIndex);
      const duplicateChunk =
        input.status !== "failed" &&
        Boolean(input.payloadHash) &&
        plainObject(sectionChunks[chunkKey]).payloadHash === input.payloadHash;
      const nextSectionStatus =
        input.status === "failed"
          ? "failed"
          : input.chunkIndex >= input.chunkCount - 1
            ? "uploaded"
            : "uploading";

      sectionUploadStatus[input.section] = sanitizeForStorage({
        status: nextSectionStatus,
        totalItems: input.totalItems ?? itemCount,
        uploadedItems:
          input.status === "failed"
            ? 0
            : input.chunkIndex === input.chunkCount - 1
              ? input.totalItems ?? itemCount
              : undefined,
        chunkIndex: input.chunkIndex,
        chunkCount: input.chunkCount,
        payloadHash: input.payloadHash,
        errorCode: input.errorCode,
        uploadedAt: new Date().toISOString()
      });

      if (input.payloadHash) {
        sectionChunks[chunkKey] = sanitizeForStorage({
          payloadHash: input.payloadHash,
          status: nextSectionStatus,
          uploadedAt: new Date().toISOString()
        });
        sectionUploadChunks[input.section] = sectionChunks;
      }

      const auditLog = [
        ...jsonArray(current.auditLog),
        sanitizeForStorage({
          action:
            input.status === "failed"
              ? "section_upload_failed"
              : duplicateChunk
                ? "section_upload_retry_acknowledged"
                : "section_uploaded",
          source: "siderascan_scanner",
          section: input.section,
          chunkIndex: input.chunkIndex,
          chunkCount: input.chunkCount,
          totalItems: input.totalItems ?? itemCount,
          errorCode: input.errorCode,
          createdAt: new Date().toISOString()
        })
      ];

      const updateData: Prisma.ScanResultUpdateInput = {
        integrity: sanitizeForStorage({
          ...integrity,
          uploadMode: "chunked",
          sectionUploadStatus,
          sectionUploadChunks,
          sectionUploadFailed: Object.values(sectionUploadStatus).some(
            (value) => plainObject(value).status === "failed"
          ),
          sectionUploadCompleted: Object.entries(sectionUploadStatus)
            .filter(([, value]) => plainObject(value).status === "uploaded")
            .map(([section]) => section)
        }),
        auditLog: sanitizeJsonArray(auditLog)
      };

      if (input.status !== "failed" && !duplicateChunk) {
        if (jsonResultSections.has(input.section)) {
          const existingRows =
            input.chunkIndex > 0
              ? jsonArray(current[input.section as keyof typeof current])
              : [];
          const mergedRows =
            input.chunkIndex > 0
              ? [...existingRows, ...sanitizedItems]
              : sanitizedItems;
          Object.assign(updateData, {
            [input.section]: sanitizeJsonArray(mergedRows)
          });
        } else {
          await this.replaceOrAppendRelationalSection(
            tx,
            scanSessionId,
            session.accountId,
            input.section,
            sanitizedItems,
            input.chunkIndex === 0
          );
        }
      } else if (duplicateChunk) {
        uploadedItems = 0;
      }

      await tx.scanResult.update({
        where: { scanSessionId },
        data: updateData
      });

      await tx.scanSession.update({
        where: { id: scanSessionId },
        data: { status: ScanStatus.UPLOADING }
      });
    });

    return {
      status: "ok",
      scanSessionId,
      section: input.section,
      uploadedItems
    };
  }

  private async replaceOrAppendRelationalSection(
    tx: Prisma.TransactionClient,
    scanSessionId: string,
    accountId: string,
    section: ChunkedResultSection,
    items: unknown[],
    replaceExisting: boolean
  ) {
    if (section === "launcherProfiles") {
      if (replaceExisting) {
        await tx.launcherProfile.deleteMany({ where: { scanSessionId } });
      }
      if (items.length > 0) {
        await tx.launcherProfile.createMany({
          data: items.map((item) => {
            const profile = plainObject(item);
            return {
              scanSessionId,
              accountId,
              profileName: stringField(profile.profileName, "Unknown", 160),
              launcherType: stringField(profile.launcherType, "unknown", 80),
              version: optionalText(
                typeof profile.version === "string"
                  ? profile.version
                  : undefined
              ),
              channel: optionalText(
                typeof profile.channel === "string"
                  ? profile.channel
                  : undefined
              ),
              pathMasked: optionalText(
                typeof profile.path === "string" ? profile.path : undefined
              ),
              executableHash: optionalText(
                typeof profile.executableHash === "string"
                  ? profile.executableHash
                  : undefined
              ),
              publisher: optionalText(
                typeof profile.publisher === "string"
                  ? profile.publisher
                  : undefined
              ),
              status: optionalStatus(
                typeof profile.status === "string"
                  ? profile.status
                  : undefined
              ),
              tags: sanitizeJsonArray(profile.tags ?? []),
              installTime: dateFromUnknown(profile.installTime),
              updateTime: dateFromUnknown(profile.updateTime),
              lastLaunchTime: dateFromUnknown(profile.lastLaunchTime),
              metadata: sanitizeForStorage(profile.metadata)
            };
          })
        });
      }
      return;
    }

    if (section === "clientModAssets") {
      if (replaceExisting) {
        await tx.clientModAsset.deleteMany({ where: { scanSessionId } });
      }
      if (items.length > 0) {
        await tx.clientModAsset.createMany({
          data: items.map((item) => {
            const asset = plainObject(item);
            return {
              scanSessionId,
              accountId,
              name: stringField(asset.name, "Unknown", 160),
              sourceLauncher: optionalText(
                typeof asset.sourceLauncher === "string"
                  ? asset.sourceLauncher
                  : undefined
              ),
              pathMasked: optionalText(
                typeof asset.path === "string" ? asset.path : undefined
              ),
              fileCount:
                typeof asset.fileCount === "number"
                  ? Math.trunc(asset.fileCount)
                  : undefined,
              totalSize:
                typeof asset.totalSize === "number"
                  ? BigInt(Math.trunc(asset.totalSize))
                  : null,
              createdTime: dateFromUnknown(asset.createdTime),
              modifiedTime: dateFromUnknown(asset.modifiedTime),
              status: optionalStatus(
                typeof asset.status === "string" ? asset.status : undefined
              ),
              metadata: sanitizeForStorage(asset.metadata)
            };
          })
        });
      }
      return;
    }

    if (section === "processTimes") {
      if (replaceExisting) {
        await tx.processTime.deleteMany({ where: { scanSessionId } });
      }
      if (items.length > 0) {
        await tx.processTime.createMany({
          data: items.map((item) => {
            const processTime = plainObject(item);
            return {
              scanSessionId,
              accountId,
              processName: stringField(processTime.processName, "Unknown", 160),
              pathMasked: optionalText(
                typeof processTime.path === "string"
                  ? processTime.path
                  : undefined
              ),
              firstSeenAt: dateFromUnknown(processTime.firstSeenAt),
              lastSeenAt: dateFromUnknown(processTime.lastSeenAt),
              startedAt: dateFromUnknown(processTime.startedAt),
              endedAt: dateFromUnknown(processTime.endedAt),
              durationMs:
                typeof processTime.durationMs === "number"
                  ? Math.trunc(processTime.durationMs)
                  : undefined,
              source: optionalText(
                typeof processTime.source === "string"
                  ? processTime.source
                  : undefined
              ),
              status: optionalStatus(
                typeof processTime.status === "string"
                  ? processTime.status
                  : undefined
              ),
              metadata: sanitizeForStorage(processTime.metadata)
            };
          })
        });
      }
      return;
    }

    if (section === "fileLogs") {
      if (replaceExisting) {
        await tx.fileLog.deleteMany({ where: { scanSessionId } });
      }
      if (items.length > 0) {
        await tx.fileLog.createMany({
          data: items.map((item) => {
            const fileLog = plainObject(item);
            const severityText =
              typeof fileLog.severity === "string"
                ? fileLog.severity.toUpperCase()
                : "";
            return {
              scanSessionId,
              accountId,
              action: stringField(fileLog.action, "unknown", 80).toLowerCase(),
              pathMasked: optionalText(
                typeof fileLog.path === "string" ? fileLog.path : undefined
              ),
              oldPathMasked: optionalText(
                typeof fileLog.oldPath === "string"
                  ? fileLog.oldPath
                  : undefined
              ),
              newPathMasked: optionalText(
                typeof fileLog.newPath === "string"
                  ? fileLog.newPath
                  : undefined
              ),
              timestamp: dateFromUnknown(fileLog.timestamp),
              source: optionalText(
                typeof fileLog.source === "string"
                  ? fileLog.source
                  : undefined
              ),
              confidence:
                typeof fileLog.confidence === "number"
                  ? Math.trunc(fileLog.confidence)
                  : undefined,
              relatedProcess: optionalText(
                typeof fileLog.relatedProcess === "string"
                  ? fileLog.relatedProcess
                  : undefined
              ),
              severity:
                severityText in Severity
                  ? Severity[severityText as keyof typeof Severity]
                  : Severity.INFO,
              metadata: sanitizeForStorage(fileLog.metadata)
            };
          })
        });
      }
      return;
    }

    throw new BadRequestException("Unsupported chunked result section");
  }

  async completeSession(
    scanSessionId: string,
    input: CompleteScanInput,
    sourceIp?: string
  ) {
    const session = await this.getUploadSessionOrRecord(
      scanSessionId,
      input,
      sourceIp
    );
    const scanStatus =
      input.status === "FAILED"
        ? ScanStatus.FAILED
        : input.status === "PARTIAL"
          ? ScanStatus.PARTIAL
          : ScanStatus.COMPLETED;

    await this.prisma.scanSession.update({
      where: { id: session.id },
      data: {
        status: scanStatus,
        finishedAt: new Date()
      }
    });

    if (input.telemetry) {
      const existingResult = await this.prisma.scanResult.findUnique({
        where: { scanSessionId },
        select: { integrity: true, auditLog: true }
      });
      const safeTelemetry = sanitizeForStorage(input.telemetry);
      await this.prisma.scanResult.updateMany({
        where: { scanSessionId },
        data: {
          integrity: sanitizeForStorage({
            ...plainObject(existingResult?.integrity),
            scannerCompleteTelemetry: safeTelemetry
          }),
          auditLog: sanitizeJsonArray([
            ...jsonArray(existingResult?.auditLog),
            {
              action: "scanner_complete_telemetry",
              source: "siderascan_scanner",
              telemetry: safeTelemetry,
              createdAt: new Date().toISOString()
            }
          ])
        }
      });
    }

    if (scanStatus === ScanStatus.COMPLETED || scanStatus === ScanStatus.PARTIAL) {
      this.triggerScanCompletedWithoutBlockingScanner(session);
    }

    return {
      status: "ok",
      scanSessionId,
      scanStatus
    };
  }

  private async applyDeviceFingerprint(
    tx: Prisma.TransactionClient,
    session: ScanSession,
    fingerprint?: IncomingDeviceFingerprint
  ) {
    if (!fingerprint) {
      return [];
    }

    const fingerprintHash = sanitizeText(fingerprint.hash.trim());
    const fingerprintPrefix = getDeviceFingerprintPrefix(fingerprintHash);
    const now = new Date();
    const existingSessionDeviceId = session.deviceId;
    let deviceId = existingSessionDeviceId;

    if (existingSessionDeviceId) {
      const existingDevice = await tx.device.findUnique({
        where: { id: existingSessionDeviceId },
        select: { fingerprintHash: true, id: true }
      });

      if (!existingDevice || existingDevice.fingerprintHash !== fingerprintHash) {
        throw new BadRequestException("Device fingerprint mismatch");
      }
    } else {
      const device = await tx.device.upsert({
        where: { fingerprintHash },
        create: {
          fingerprintHash,
          fingerprintPrefix,
          fingerprintVersion: fingerprint.version,
          fingerprintConfidence: normalizeFingerprintConfidence(
            fingerprint.confidence
          ),
          firstSeenAt: now,
          lastSeenAt: now,
          scanCount: 1
        },
        update: {
          fingerprintVersion: fingerprint.version,
          fingerprintConfidence: normalizeFingerprintConfidence(
            fingerprint.confidence
          ),
          lastSeenAt: now,
          scanCount: { increment: 1 }
        },
        select: {
          id: true
        }
      });
      deviceId = device.id;

      await tx.deviceAccountLink.upsert({
        where: {
          deviceId_accountId: {
            deviceId: device.id,
            accountId: session.accountId
          }
        },
        create: {
          deviceId: device.id,
          accountId: session.accountId,
          firstSeenAt: now,
          lastSeenAt: now,
          scanCount: 1
        },
        update: {
          lastSeenAt: now,
          scanCount: { increment: 1 }
        }
      });

      await tx.scanSession.update({
        where: { id: session.id },
        data: { deviceId: device.id }
      });
    }

    if (!deviceId) {
      return [];
    }

    const activeMark = await this.findActiveDeviceMark(
      tx,
      deviceId,
      session.accountId,
      now
    );

    if (
      !activeMark ||
      (activeMark.status !== DeviceMarkStatus.BANNED &&
        activeMark.status !== DeviceMarkStatus.SUSPICIOUS)
    ) {
      return [];
    }

    const severity = markSeverity(activeMark.status);

    return [
      {
        category: FindingCategory.DEVICE,
        severity,
        title:
          activeMark.status === DeviceMarkStatus.BANNED
            ? "Banned HWID match"
            : "Suspicious HWID match",
        message: `Device fingerprint ${fingerprintPrefix} matches an active ${activeMark.status.toLowerCase()} device mark.`,
        confidence: 100,
        sourceModule: "device_hwid_marks",
        evidenceRef: null,
        ruleId: null,
        metadata: sanitizeForStorage({
          deviceId,
          fingerprintPrefix,
          markId: activeMark.id,
          markScope: activeMark.scope,
          markStatus: activeMark.status,
          reason: activeMark.reason
        })
      }
    ];
  }

  private async findActiveDeviceMark(
    tx: Prisma.TransactionClient,
    deviceId: string,
    accountId: string,
    now: Date
  ) {
    const marks = await tx.deviceMark.findMany({
      where: {
        deviceId,
        AND: [
          { revokedAt: null },
          { OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] },
          {
            OR: [
              { scope: DeviceMarkScope.GLOBAL, accountId: null },
              { scope: DeviceMarkScope.ACCOUNT, accountId }
            ]
          }
        ]
      }
    });

    return marks.sort((left, right) => {
      const rankDelta = markRank(right.status) - markRank(left.status);

      if (rankDelta !== 0) {
        return rankDelta;
      }

      if (left.scope !== right.scope) {
        return left.scope === DeviceMarkScope.ACCOUNT ? -1 : 1;
      }

      return right.markedAt.getTime() - left.markedAt.getTime();
    })[0];
  }

  private invalid(errorCode: string, message: string) {
    return {
      valid: false,
      errorCode,
      message
    };
  }

  private async getUploadSession(
    scanSessionId: string,
    input: { uploadToken: string; nonce: string }
  ) {
    const session = await this.prisma.scanSession.findUnique({
      where: { id: scanSessionId }
    });

    if (!session || session.expiresAt <= new Date()) {
      throw new UnauthorizedException("Invalid upload session");
    }

    if (
      !safeHashEquals(input.uploadToken, session.uploadTokenHash) ||
      !safeHashEquals(input.nonce, session.nonceHash)
    ) {
      throw new UnauthorizedException("Invalid upload session");
    }

    return session;
  }

  private async getUploadSessionOrRecord(
    scanSessionId: string,
    input: { uploadToken: string; nonce: string },
    sourceIp?: string
  ) {
    try {
      return await this.getUploadSession(scanSessionId, input);
    } catch (error) {
      const session = await this.prisma.scanSession.findUnique({
        where: { id: scanSessionId },
        select: { accountId: true, scannerKeyId: true }
      });

      await this.monitoring.recordSecurityEvent({
        accountId: session?.accountId,
        eventType: "SCANNER_UPLOAD_AUTH_FAILED",
        message: "Scanner upload session authentication failed.",
        metadata: {
          scanSessionId,
          scannerKeyId: session?.scannerKeyId ?? null
        },
        severity: MonitoringSeverity.HIGH,
        sourceIp
      });

      throw error;
    }
  }

  private triggerScanCompletedWithoutBlockingScanner(session: ScanSession) {
    void this.scanReviews.triggerScanCompleted(session.id).catch(async (error) => {
      const message =
        error instanceof Error ? error.message : "scan.completed automation failed";

      try {
        await this.monitoring.recordMonitoringEvent({
          accountId: session.accountId,
          eventType: "SCAN_COMPLETED_AUTOMATION_TRIGGER_FAILED",
          message:
            "Scan completed, but scan.completed automation trigger failed.",
          metadata: {
            scanSessionId: session.id,
            lastError: message
          },
          service: "n8n",
          severity: MonitoringSeverity.WARNING
        });
      } catch {
        // Automation/monitoring failures must never block scanner completion.
      }
    });
  }

  private normalizeFindings(findings: IncomingFinding[]) {
    return findings.map((finding) => ({
      category: finding.category ?? FindingCategory.OVERVIEW,
      severity: finding.severity ?? Severity.INFO,
      title: sanitizeText(finding.title.trim()),
      message: sanitizeText(finding.message.trim()),
      confidence: finding.confidence ?? 100,
      sourceModule: finding.sourceModule?.trim() || null,
      evidenceRef: finding.evidenceRef?.trim() || null,
      ruleId: finding.ruleId?.trim() || null,
      metadata: sanitizeForStorage(finding.metadata)
    }));
  }
}
