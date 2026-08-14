import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException
} from "@nestjs/common";
import {
  AccountRole,
  AiRecommendedAction,
  AutomationEventStatus,
  GlobalRole,
  MonitoringSeverity,
  ScanReviewStatus
} from "@prisma/client";
import { env } from "../config/env";
import { MonitoringService } from "../monitoring/monitoring.service";
import { sanitizeForStorage } from "../common/data-sanitizer";
import { PrismaService } from "../prisma/prisma.service";
import type { AuthUser } from "../auth/auth.types";
import { bodyToSignedString, signN8nPayload } from "./scan-review-signature";

export type AiReviewInput = {
  scanSessionId: string;
  assessment: string;
  confidence: number;
  summaryForModerator: string;
  summaryForPlayer?: string;
  recommendedAction: AiRecommendedAction;
  keyIndicators: unknown[];
  possibleFalsePositives: unknown[];
  contradictions: unknown[];
  moderatorChecklist: unknown[];
  questionsForPlayer: unknown[];
  evidenceReferences: Array<{
    findingId?: string;
    evidenceId?: string;
    label?: string;
    note?: string;
  }>;
  model?: string;
  promptVersion?: string;
  inputHash?: string;
  generatedAt: Date;
};

const eventType = "scan.completed";
const n8nDispatchTimeoutMs = 10_000;

function idempotencyKeyFor(scanSessionId: string) {
  return `${eventType}:${scanSessionId}`;
}

function severityCounts(
  findings: Array<{ severity: string }>
): Record<string, number> {
  return findings.reduce<Record<string, number>>((counts, finding) => {
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;

    return counts;
  }, {});
}

function jsonRows(value: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter(
    (item): item is Record<string, unknown> =>
      Boolean(item) && typeof item === "object" && !Array.isArray(item)
  );
}

function stringValue(value: unknown) {
  return typeof value === "string" ? value.trim() : "";
}

function summarizeForensicRows(rows: Array<Record<string, unknown>>) {
  const statusCounts: Record<string, number> = {};
  const severityCounts: Record<string, number> = {};
  const topReviewItems: string[] = [];

  for (const row of rows) {
    const status = stringValue(row.status) || "UNKNOWN";
    const severity = stringValue(row.severity) || "INFO";
    statusCounts[status] = (statusCounts[status] ?? 0) + 1;
    severityCounts[severity] = (severityCounts[severity] ?? 0) + 1;

    if (
      topReviewItems.length < 8 &&
      ["review", "suspicious", "flagged", "missing_file"].includes(
        status.toLowerCase()
      )
    ) {
      const label =
        stringValue(row.name) ||
        stringValue(row.displayName) ||
        stringValue(row.driverName) ||
        stringValue(row.persistenceType) ||
        "Review item";
      topReviewItems.push(label);
    }
  }

  return {
    total: rows.length,
    statusCounts,
    severityCounts,
    topReviewItems
  };
}

function firstText(row: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = stringValue(row[key]);

    if (value) {
      return value;
    }
  }

  return null;
}

function shortText(value: unknown, max = 180) {
  const text = stringValue(value);

  if (!text) {
    return null;
  }

  return text.length > max ? `${text.slice(0, max - 1)}...` : text;
}

function rowTime(row: Record<string, unknown>) {
  return (
    firstText(row, [
      "timestamp",
      "startedAt",
      "createdAt",
      "modifiedTime",
      "firstSeenAt",
      "lastSeenAt"
    ]) ?? null
  );
}

function compactTimelineRows(rows: Array<Record<string, unknown>>) {
  return rows
    .map((row) => ({
      timestamp: rowTime(row),
      sourceModule: firstText(row, ["sourceModule", "source"]),
      eventType: firstText(row, ["eventType", "action", "type"]),
      title:
        firstText(row, ["title", "subject", "name", "processName"]) ??
        "Timeline item",
      processName: firstText(row, ["processName", "targetProcessName"]),
      path: shortText(firstText(row, ["path", "sourcePath", "imagePath"])),
      severity: firstText(row, ["severity"]) ?? "INFO",
      status: firstText(row, ["status"]) ?? "context",
      confidence: row.confidence ?? null,
      reasonFlags: Array.isArray(row.reasonFlags)
        ? row.reasonFlags.slice(0, 8)
        : Array.isArray(row.suspiciousFlags)
          ? row.suspiciousFlags.slice(0, 8)
          : []
    }))
    .filter((row) => row.timestamp || row.title || row.processName)
    .slice(0, 30);
}

function compactProcessRows(rows: Array<Record<string, unknown>>) {
  return rows
    .filter((row) => {
      const status = stringValue(row.status).toLowerCase();

      return status !== "limited" || Boolean(firstText(row, ["path", "commandLine"]));
    })
    .map((row) => ({
      processName: firstText(row, ["processName", "name"]) ?? "Unknown",
      pid: row.pid ?? null,
      parent: firstText(row, ["parentName", "parent"]),
      startedAt: rowTime(row),
      path: shortText(firstText(row, ["path", "exePath", "executablePath"])),
      commandLine: shortText(row.commandLine, 220),
      signer: firstText(row, ["signer", "publisher"]),
      signatureStatus: firstText(row, ["signatureStatus"]),
      networkSummary: row.networkSummary ?? null,
      suspiciousFlags: Array.isArray(row.suspiciousFlags)
        ? row.suspiciousFlags.slice(0, 8)
        : [],
      status: firstText(row, ["status"]) ?? "running",
      confidence: row.confidence ?? null
    }))
    .slice(0, 35);
}

function compactReviewRows(
  rows: Array<Record<string, unknown>>,
  titleKeys: string[],
  limit = 12
) {
  return rows
    .filter((row) => {
      const status = stringValue(row.status).toLowerCase();
      const severity = stringValue(row.severity).toUpperCase();

      return (
        ["review", "suspicious", "flagged", "missing_file"].includes(status) ||
        ["WARNING", "SEVERE", "CRITICAL"].includes(severity)
      );
    })
    .map((row) => ({
      title: firstText(row, titleKeys) ?? "Review item",
      timestamp: rowTime(row),
      path: shortText(firstText(row, ["path", "sourcePath", "imagePath", "command"])),
      processName: firstText(row, [
        "processName",
        "targetProcessName",
        "sourceProcessName"
      ]),
      severity: firstText(row, ["severity"]) ?? "INFO",
      status: firstText(row, ["status"]) ?? "review",
      confidence: row.confidence ?? null,
      reasonFlags: Array.isArray(row.reasonFlags)
        ? row.reasonFlags.slice(0, 8)
        : Array.isArray(row.suspiciousFlags)
          ? row.suspiciousFlags.slice(0, 8)
          : []
    }))
    .slice(0, limit);
}

function reviewContext(result?: {
  processTimeline: unknown;
  loadedModules: unknown;
  processHandles: unknown;
  services: unknown;
  drivers: unknown;
  persistenceItems: unknown;
  eventLogs: unknown;
  defenderEvents: unknown;
  executionArtifacts: unknown;
  fileTriage: unknown;
  networkConnections: unknown;
  forensicTimeline: unknown;
}) {
  if (!result) {
    return null;
  }

  const processTimeline = jsonRows(result.processTimeline);
  const forensicTimeline = jsonRows(result.forensicTimeline);
  const networkConnections = jsonRows(result.networkConnections);

  return sanitizeForStorage({
    activeProcesses: compactProcessRows(processTimeline),
    recentTimeline: compactTimelineRows(forensicTimeline),
    reviewHighlights: {
      loadedModules: compactReviewRows(jsonRows(result.loadedModules), [
        "moduleName",
        "name",
        "title"
      ]),
      processHandles: compactReviewRows(jsonRows(result.processHandles), [
        "sourceProcessName",
        "targetProcessName",
        "title"
      ]),
      services: compactReviewRows(jsonRows(result.services), [
        "name",
        "displayName",
        "title"
      ]),
      drivers: compactReviewRows(jsonRows(result.drivers), [
        "driverName",
        "name",
        "title"
      ]),
      persistence: compactReviewRows(jsonRows(result.persistenceItems), [
        "name",
        "persistenceType",
        "title"
      ]),
      eventLogs: compactReviewRows(jsonRows(result.eventLogs), [
        "title",
        "eventId",
        "provider"
      ]),
      defender: compactReviewRows(jsonRows(result.defenderEvents), [
        "title",
        "eventId",
        "provider"
      ]),
      executionArtifacts: compactReviewRows(jsonRows(result.executionArtifacts), [
        "name",
        "title",
        "artifactType"
      ]),
      fileTriage: compactReviewRows(jsonRows(result.fileTriage), [
        "filename",
        "name",
        "title"
      ])
    },
    networkHighlights: networkConnections
      .map((row) => ({
        processName: firstText(row, ["processName", "name"]),
        state: firstText(row, ["state", "status"]),
        remoteAddress: firstText(row, ["remoteAddress", "remoteIp", "remote"]),
        remotePort: row.remotePort ?? null,
        severity: firstText(row, ["severity"]) ?? "INFO",
        confidence: row.confidence ?? null,
        reasonFlags: Array.isArray(row.reasonFlags)
          ? row.reasonFlags.slice(0, 8)
          : []
      }))
      .slice(0, 20)
  });
}

function forensicSummary(result?: {
  processTimeline: unknown;
  loadedModules: unknown;
  processHandles: unknown;
  services: unknown;
  drivers: unknown;
  persistenceItems: unknown;
  eventLogs: unknown;
  defenderEvents: unknown;
  executionArtifacts: unknown;
  fileTriage: unknown;
  networkConnections: unknown;
  dnsCache: unknown;
  hostsEntries: unknown;
  forensicTimeline: unknown;
  integrity: unknown;
}) {
  if (!result) {
    return null;
  }

  const processTimeline = jsonRows(result.processTimeline);
  const loadedModules = jsonRows(result.loadedModules);
  const processHandles = jsonRows(result.processHandles);
  const services = jsonRows(result.services);
  const drivers = jsonRows(result.drivers);
  const persistenceItems = jsonRows(result.persistenceItems);
  const eventLogs = jsonRows(result.eventLogs);
  const defenderEvents = jsonRows(result.defenderEvents);
  const executionArtifacts = jsonRows(result.executionArtifacts);
  const fileTriage = jsonRows(result.fileTriage);
  const networkConnections = jsonRows(result.networkConnections);
  const dnsCache = jsonRows(result.dnsCache);
  const hostsEntries = jsonRows(result.hostsEntries);
  const forensicTimeline = jsonRows(result.forensicTimeline);
  const integrity =
    result.integrity && typeof result.integrity === "object"
      ? (result.integrity as Record<string, unknown>)
      : {};

  return sanitizeForStorage({
    reviewMode:
      (integrity.af3Summary as Record<string, unknown> | undefined)?.reviewMode ??
      null,
    processTimeline: summarizeForensicRows(processTimeline),
    loadedModules: summarizeForensicRows(loadedModules),
    processHandles: summarizeForensicRows(processHandles),
    services: summarizeForensicRows(services),
    drivers: summarizeForensicRows(drivers),
    persistenceItems: summarizeForensicRows(persistenceItems),
    eventLogs: summarizeForensicRows(eventLogs),
    defenderEvents: summarizeForensicRows(defenderEvents),
    executionArtifacts: summarizeForensicRows(executionArtifacts),
    fileTriage: summarizeForensicRows(fileTriage),
    networkConnections: summarizeForensicRows(networkConnections),
    dnsCache: summarizeForensicRows(dnsCache),
    hostsEntries: summarizeForensicRows(hostsEntries),
    forensicTimeline: {
      ...summarizeForensicRows(forensicTimeline),
      correlationCount:
        typeof (integrity.af7Summary as Record<string, unknown> | undefined)
          ?.correlationFindings === "number"
          ? (integrity.af7Summary as Record<string, unknown>).correlationFindings
          : 0,
      topCorrelations:
        (integrity.af7Summary as Record<string, unknown> | undefined)
          ?.topCorrelations ?? []
    }
  });
}

function newestActiveDeviceMark(
  marks: Array<{
    status: string;
    scope: string;
    accountId: string | null;
    revokedAt: Date | null;
    expiresAt: Date | null;
    markedAt: Date;
  }>,
  accountId: string
) {
  const now = new Date();

  return marks
    .filter((mark) => !mark.revokedAt)
    .filter((mark) => !mark.expiresAt || mark.expiresAt > now)
    .filter(
      (mark) =>
        (mark.scope === "GLOBAL" && mark.accountId === null) ||
        (mark.scope === "ACCOUNT" && mark.accountId === accountId)
    )
    .sort((left, right) => right.markedAt.getTime() - left.markedAt.getTime())[0];
}

@Injectable()
export class ScanReviewsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly monitoring: MonitoringService
  ) {}

  async triggerScanCompleted(scanSessionId: string, force = false) {
    const scan = await this.prisma.scanSession.findUnique({
      where: { id: scanSessionId },
      include: {
        account: { select: { id: true, name: true } },
        device: {
          select: {
            fingerprintPrefix: true,
            marks: {
              select: {
                status: true,
                scope: true,
                accountId: true,
                revokedAt: true,
                expiresAt: true,
                markedAt: true
              }
            }
          }
        },
        findings: {
          orderBy: [{ severity: "desc" }, { createdAt: "desc" }],
          select: {
            id: true,
            severity: true,
            category: true,
            title: true,
            message: true,
            confidence: true,
            sourceModule: true,
            evidenceId: true,
            metadata: true
          }
        },
        evidence: {
          orderBy: { createdAt: "desc" },
          take: 30,
          select: { id: true, type: true, title: true }
        },
        result: {
          select: {
            processTimeline: true,
            loadedModules: true,
            processHandles: true,
            services: true,
            drivers: true,
            persistenceItems: true,
            eventLogs: true,
            defenderEvents: true,
            executionArtifacts: true,
            fileTriage: true,
            networkConnections: true,
            dnsCache: true,
            hostsEntries: true,
            forensicTimeline: true,
            integrity: true
          }
        },
        _count: { select: { evidence: true, findings: true } }
      }
    });

    if (!scan) {
      throw new NotFoundException("Scan not found");
    }

    const currentDeviceMark = scan.device
      ? newestActiveDeviceMark(scan.device.marks, scan.accountId)
      : null;
    const payload = sanitizeForStorage({
      event: eventType,
      scanId: scan.id,
      accountId: scan.accountId,
      accountName: scan.account.name,
      riskScore: scan.riskScore,
      severity: scan.maxSeverity,
      reviewStatus: scan.reviewStatus,
      scannerVersion: scan.scannerVersion,
      playerLabel: scan.playerLabel,
      findingCount: scan._count.findings,
      evidenceCount: scan._count.evidence,
      findingSeverityCounts: severityCounts(scan.findings),
      forensicSummary: forensicSummary(scan.result ?? undefined),
      reviewContext: reviewContext(scan.result ?? undefined),
      topFindings: scan.findings
        .filter((finding) => finding.sourceModule !== "scanner_phase1")
        .slice(0, 20)
        .map((finding) => ({
          id: finding.id,
          severity: finding.severity,
          category: finding.category,
          title: finding.title,
          message: finding.message,
          confidence: finding.confidence,
          sourceModule: finding.sourceModule,
          evidenceId: finding.evidenceId,
          metadata: sanitizeForStorage(finding.metadata)
        })),
      evidenceReferences: scan.evidence.map((evidence) => ({
        id: evidence.id,
        type: evidence.type,
        title: evidence.title
      })),
      device: scan.device
        ? {
            fingerprintPrefix: scan.device.fingerprintPrefix,
            markStatus: currentDeviceMark?.status ?? null
          }
        : null,
      dashboardUrl: `${env.APP_DASHBOARD_URL}/scans/${scan.id}`
    });
    const idempotencyKey = idempotencyKeyFor(scan.id);

    const event = await this.prisma.automationEvent.upsert({
      where: { idempotencyKey },
      create: {
        eventType,
        idempotencyKey,
        scanSessionId: scan.id,
        accountId: scan.accountId,
        status: AutomationEventStatus.PENDING,
        payload
      },
      update: {
        payload,
        status: AutomationEventStatus.PENDING,
        lastError: null
      }
    });

    await this.prisma.scanSession.update({
      where: { id: scan.id },
      data: { reviewStatus: ScanReviewStatus.PENDING }
    });

    return this.dispatchAutomationEvent(event.id, force);
  }

  async dispatchAutomationEvent(eventId: string, force = false) {
    const event = await this.prisma.automationEvent.findUnique({
      where: { id: eventId }
    });

    if (!event) {
      throw new NotFoundException("Automation event not found");
    }

    if (!env.N8N_WEBHOOK_ENABLED) {
      await this.monitoring.recordMonitoringEvent({
        eventType: "N8N_SCAN_COMPLETED_DISABLED",
        message: "n8n scan completed webhook is disabled.",
        metadata: { automationEventId: event.id },
        service: "n8n",
        severity: MonitoringSeverity.INFO
      });

      return this.prisma.automationEvent.update({
        where: { id: event.id },
        data: {
          status: AutomationEventStatus.DISABLED,
          lastError: "n8n webhook disabled",
          lastAttemptAt: new Date()
        }
      });
    }

    if (!env.N8N_SCAN_COMPLETED_WEBHOOK_URL) {
      return this.failEvent(event.id, "N8N_SCAN_COMPLETED_WEBHOOK_URL is not configured");
    }

    if (!force && event.attemptCount >= env.N8N_MAX_ATTEMPTS) {
      return event;
    }

    const timestamp = Math.floor(Date.now() / 1000).toString();
    const body = bodyToSignedString(event.payload);
    const signature = signN8nPayload(timestamp, body);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), n8nDispatchTimeoutMs);

    try {
      const response = await fetch(env.N8N_SCAN_COMPLETED_WEBHOOK_URL, {
        body,
        headers: {
          "content-type": "application/json",
          "x-idempotency-key": event.idempotencyKey,
          "x-siderascan-event": event.eventType,
          "x-siderascan-signature": signature,
          "x-siderascan-timestamp": timestamp
        },
        method: "POST",
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`n8n responded with status ${response.status}`);
      }

      return this.prisma.automationEvent.update({
        where: { id: event.id },
        data: {
          status: AutomationEventStatus.SENT,
          attemptCount: { increment: 1 },
          lastError: null,
          lastAttemptAt: new Date()
        }
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "n8n request failed";

      return this.failEvent(event.id, message);
    } finally {
      clearTimeout(timeout);
    }
  }

  async submitAiReview(input: AiReviewInput) {
    const scan = await this.prisma.scanSession.findUnique({
      where: { id: input.scanSessionId },
      select: { id: true, accountId: true }
    });

    if (!scan) {
      throw new NotFoundException("Scan not found");
    }

    const evidenceReferences = input.evidenceReferences ?? [];
    const findingIds = evidenceReferences
      .map((reference) => reference.findingId)
      .filter((id): id is string => Boolean(id));
    const evidenceIds = evidenceReferences
      .map((reference) => reference.evidenceId)
      .filter((id): id is string => Boolean(id));

    const [findings, evidence] = await this.prisma.$transaction([
      this.prisma.scanFinding.findMany({
        where: { scanSessionId: scan.id, id: { in: findingIds } },
        select: { id: true }
      }),
      this.prisma.scanEvidence.findMany({
        where: { scanSessionId: scan.id, id: { in: evidenceIds } },
        select: { id: true }
      })
    ]);
    const validFindingIds = new Set(findings.map((finding) => finding.id));
    const validEvidenceIds = new Set(evidence.map((item) => item.id));

    const review = await this.prisma.$transaction(async (tx) => {
      const savedReview = await tx.aiReview.upsert({
        where: { scanSessionId: scan.id },
        create: {
          scanSessionId: scan.id,
          accountId: scan.accountId,
          assessment: input.assessment,
          confidence: input.confidence,
          summaryForModerator: input.summaryForModerator,
          summaryForPlayer: input.summaryForPlayer ?? null,
          recommendedAction: input.recommendedAction,
          keyIndicators: sanitizeForStorage(input.keyIndicators),
          possibleFalsePositives: sanitizeForStorage(input.possibleFalsePositives),
          contradictions: sanitizeForStorage(input.contradictions),
          moderatorChecklist: sanitizeForStorage(input.moderatorChecklist),
          questionsForPlayer: sanitizeForStorage(input.questionsForPlayer),
          evidenceReferences: sanitizeForStorage(input.evidenceReferences),
          model: input.model ?? null,
          promptVersion: input.promptVersion ?? null,
          inputHash: input.inputHash ?? null,
          generatedAt: input.generatedAt
        },
        update: {
          assessment: input.assessment,
          confidence: input.confidence,
          summaryForModerator: input.summaryForModerator,
          summaryForPlayer: input.summaryForPlayer ?? null,
          recommendedAction: input.recommendedAction,
          keyIndicators: sanitizeForStorage(input.keyIndicators),
          possibleFalsePositives: sanitizeForStorage(input.possibleFalsePositives),
          contradictions: sanitizeForStorage(input.contradictions),
          moderatorChecklist: sanitizeForStorage(input.moderatorChecklist),
          questionsForPlayer: sanitizeForStorage(input.questionsForPlayer),
          evidenceReferences: sanitizeForStorage(input.evidenceReferences),
          model: input.model ?? null,
          promptVersion: input.promptVersion ?? null,
          inputHash: input.inputHash ?? null,
          generatedAt: input.generatedAt
        }
      });

      await tx.aiReviewEvidence.deleteMany({
        where: { aiReviewId: savedReview.id }
      });

      const linkRows = evidenceReferences
        .map((reference) => ({
          aiReviewId: savedReview.id,
          scanSessionId: scan.id,
          findingId:
            reference.findingId && validFindingIds.has(reference.findingId)
              ? reference.findingId
              : null,
          evidenceId:
            reference.evidenceId && validEvidenceIds.has(reference.evidenceId)
              ? reference.evidenceId
              : null
        }))
        .filter((reference) => reference.findingId || reference.evidenceId);

      if (linkRows.length > 0) {
        await tx.aiReviewEvidence.createMany({ data: linkRows });
      }

      await tx.scanSession.update({
        where: { id: scan.id },
        data: { reviewStatus: ScanReviewStatus.REVIEWED }
      });

      return savedReview;
    });

    return {
      status: "ok",
      scanSessionId: scan.id,
      reviewStatus: ScanReviewStatus.REVIEWED,
      aiReviewId: review.id
    };
  }

  async retryScanReview(viewer: AuthUser, scanSessionId: string) {
    const scan = await this.prisma.scanSession.findFirst({
      where: {
        id: scanSessionId,
        account:
          viewer.globalRole === GlobalRole.SUPER_ADMIN
            ? undefined
            : { memberships: { some: { userId: viewer.id } } }
      },
      include: {
        account: { select: { memberships: { where: { userId: viewer.id } } } }
      }
    });

    if (!scan) {
      throw new NotFoundException("Scan not found");
    }

    if (viewer.globalRole !== GlobalRole.SUPER_ADMIN) {
      const membership = scan.account.memberships[0];

      if (membership?.role !== AccountRole.ACCOUNT_OWNER) {
        throw new ForbiddenException("Account Owner access required");
      }
    }

    await this.triggerScanCompleted(scan.id, true);

    return {
      status: "queued",
      scanSessionId: scan.id
    };
  }

  private async failEvent(eventId: string, message: string) {
    const updated = await this.prisma.automationEvent.update({
      where: { id: eventId },
      data: {
        status: AutomationEventStatus.FAILED,
        attemptCount: { increment: 1 },
        lastError: message,
        lastAttemptAt: new Date()
      }
    });

    if (updated.scanSessionId) {
      await this.prisma.scanSession.update({
        where: { id: updated.scanSessionId },
        data: { reviewStatus: ScanReviewStatus.FAILED }
      });
    }

    await this.monitoring.recordMonitoringEvent({
      accountId: updated.accountId,
      eventType: "N8N_SCAN_COMPLETED_FAILED",
      message: "n8n scan completed delivery failed.",
      metadata: {
        automationEventId: updated.id,
        scanSessionId: updated.scanSessionId,
        lastError: message
      },
      service: "n8n",
      severity: MonitoringSeverity.HIGH
    });

    return updated;
  }
}

export function rejectAutoBanAction(action: AiRecommendedAction) {
  if (!Object.values(AiRecommendedAction).includes(action)) {
    throw new BadRequestException("Invalid recommended action");
  }
}
