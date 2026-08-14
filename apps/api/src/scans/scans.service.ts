import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from "@nestjs/common";
import {
  AccountStatus,
  AccountRole,
  DeviceMarkScope,
  DeviceMarkStatus,
  FindingCategory,
  GlobalRole,
  MonitoringSeverity,
  Prisma,
  Severity,
} from "@prisma/client";
import { AuditService } from "../audit/audit.service";
import type { AuthUser } from "../auth/auth.types";
import { sanitizeForStorage } from "../common/data-sanitizer";
import { env } from "../config/env";
import { MonitoringService } from "../monitoring/monitoring.service";
import { PrismaService } from "../prisma/prisma.service";

const scanListInclude = {
  account: { select: { id: true, name: true } },
  scannerKey: { select: { id: true, name: true, keyPrefix: true } },
  _count: { select: { findings: true } },
} satisfies Prisma.ScanSessionInclude;

const scanDetailInclude = {
  account: { select: { id: true, name: true } },
  scannerKey: { select: { id: true, name: true, keyPrefix: true } },
  device: {
    select: {
      id: true,
      fingerprintPrefix: true,
      fingerprintVersion: true,
      fingerprintConfidence: true,
      firstSeenAt: true,
      lastSeenAt: true,
      scanCount: true,
      marks: {
        include: {
          account: { select: { id: true, name: true } },
          markedBy: { select: { id: true, displayName: true } },
          evidence: true,
        },
        orderBy: { markedAt: "desc" },
      },
    },
  },
  result: true,
  modules: { orderBy: { createdAt: "asc" } },
  evidence: { orderBy: { createdAt: "asc" } },
  launcherProfiles: { orderBy: { createdAt: "asc" } },
  clientModAssets: { orderBy: { createdAt: "asc" } },
  processTimes: { orderBy: { createdAt: "asc" } },
  fileLogs: { orderBy: { timestamp: "desc" } },
  aiReview: {
    include: {
      evidenceLinks: {
        include: {
          finding: { select: { id: true, title: true, severity: true } },
          evidence: { select: { id: true, type: true, title: true } },
        },
        orderBy: { createdAt: "asc" },
      },
    },
  },
  automationEvents: {
    where: { eventType: "scan.completed" },
    orderBy: { updatedAt: "desc" },
    take: 5,
  },
  findings: {
    include: { evidence: { select: { id: true, type: true, title: true } } },
    orderBy: { createdAt: "desc" },
  },
} satisfies Prisma.ScanSessionInclude;

type ScanListItem = Prisma.ScanSessionGetPayload<{
  include: typeof scanListInclude;
}>;
type ScanDetail = Prisma.ScanSessionGetPayload<{
  include: typeof scanDetailInclude;
}>;

type FindingQuery = {
  q?: string;
  severity?: Severity;
  category?: FindingCategory;
  page?: number;
  pageSize?: number;
  sort?: "createdAt" | "severity" | "category" | "title" | "confidence";
  direction?: "asc" | "desc";
};

function markRank(status: DeviceMarkStatus) {
  return {
    [DeviceMarkStatus.BANNED]: 4,
    [DeviceMarkStatus.SUSPICIOUS]: 3,
    [DeviceMarkStatus.TRUSTED]: 2,
    [DeviceMarkStatus.CLEARED]: 1,
  }[status];
}

function activeDeviceMark(scan: ScanDetail) {
  const now = new Date();

  return scan.device?.marks
    .filter((mark) => !mark.revokedAt)
    .filter((mark) => !mark.expiresAt || mark.expiresAt > now)
    .filter(
      (mark) =>
        (mark.scope === DeviceMarkScope.GLOBAL && mark.accountId === null) ||
        (mark.scope === DeviceMarkScope.ACCOUNT &&
          mark.accountId === scan.accountId),
    )
    .sort((left, right) => {
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

function visibleAccountWhere(viewer: AuthUser): Prisma.AccountWhereInput {
  const where: Prisma.AccountWhereInput = {
    deletedAt: null,
    status: { not: AccountStatus.DELETED },
  };

  if (viewer.globalRole !== GlobalRole.SUPER_ADMIN) {
    where.memberships = { some: { userId: viewer.id } };
  }

  return where;
}

function serializeScanListItem(scan: ScanListItem) {
  return {
    id: scan.id,
    accountId: scan.accountId,
    accountName: scan.account.name,
    scannerKeyId: scan.scannerKeyId,
    scannerKeyName: scan.scannerKey.name,
    scannerKeyPrefix: scan.scannerKey.keyPrefix,
    playerLabel: scan.playerLabel,
    status: scan.status,
    scannerVersion: scan.scannerVersion,
    platform: scan.platform,
    arch: scan.arch,
    startedAt: scan.startedAt,
    finishedAt: scan.finishedAt,
    createdAt: scan.createdAt,
    expiresAt: scan.expiresAt,
    riskScore: scan.riskScore,
    maxSeverity: scan.maxSeverity,
    reviewStatus: scan.reviewStatus,
    findingCount: scan._count.findings,
  };
}

function serializeFinding(
  finding: Prisma.ScanFindingGetPayload<{
    include: { evidence: { select: { id: true; type: true; title: true } } };
  }>,
) {
  return {
    id: finding.id,
    category: finding.category,
    severity: finding.severity,
    title: finding.title,
    message: finding.message,
    ruleId: finding.ruleId,
    evidenceId: finding.evidenceId,
    evidence: finding.evidence
      ? {
          id: finding.evidence.id,
          type: finding.evidence.type,
          title: finding.evidence.title,
        }
      : null,
    confidence: finding.confidence,
    sourceModule: finding.sourceModule,
    metadata: sanitizeForStorage(finding.metadata),
    createdAt: finding.createdAt,
  };
}

function serializeScanDetail(
  scan: ScanDetail,
  auditLogs: Array<{
    id: string;
    accountId: string | null;
    actorUserId: string | null;
    action: string;
    entityType: string;
    entityId: string | null;
    before: Prisma.JsonValue | null;
    after: Prisma.JsonValue | null;
    createdAt: Date;
  }>,
) {
  const currentDeviceMark = activeDeviceMark(scan);

  return {
    id: scan.id,
    accountId: scan.accountId,
    accountName: scan.account.name,
    scannerKeyId: scan.scannerKeyId,
    scannerKeyName: scan.scannerKey.name,
    scannerKeyPrefix: scan.scannerKey.keyPrefix,
    playerLabel: scan.playerLabel,
    status: scan.status,
    scannerVersion: scan.scannerVersion,
    platform: scan.platform,
    arch: scan.arch,
    startedAt: scan.startedAt,
    finishedAt: scan.finishedAt,
    createdAt: scan.createdAt,
    expiresAt: scan.expiresAt,
    riskScore: scan.riskScore,
    maxSeverity: scan.maxSeverity,
    reviewStatus: scan.reviewStatus,
    device: scan.device
      ? {
          id: scan.device.id,
          fingerprintPrefix: scan.device.fingerprintPrefix,
          fingerprintVersion: scan.device.fingerprintVersion,
          fingerprintConfidence: scan.device.fingerprintConfidence,
          firstSeenAt: scan.device.firstSeenAt,
          lastSeenAt: scan.device.lastSeenAt,
          scanCount: scan.device.scanCount,
          currentMark: currentDeviceMark
            ? {
                id: currentDeviceMark.id,
                scope: currentDeviceMark.scope,
                accountId: currentDeviceMark.accountId,
                accountName: currentDeviceMark.account?.name ?? null,
                status: currentDeviceMark.status,
                severity: currentDeviceMark.severity,
                reason: currentDeviceMark.reason,
                markedAt: currentDeviceMark.markedAt,
                markedBy: currentDeviceMark.markedBy,
                expiresAt: currentDeviceMark.expiresAt,
                evidence: currentDeviceMark.evidence.map((evidence) => ({
                  id: evidence.id,
                  scanSessionId: evidence.scanSessionId,
                  findingId: evidence.findingId,
                  note: evidence.note,
                  createdAt: evidence.createdAt,
                })),
              }
            : null,
        }
      : null,
    result: scan.result
      ? {
          id: scan.result.id,
          payloadHash: scan.result.payloadHash,
          overview: sanitizeForStorage(scan.result.overview),
          systemIdentity: sanitizeForStorage(scan.result.systemIdentity),
          networkSnapshot: sanitizeForStorage(scan.result.networkSnapshot),
          integrity: sanitizeForStorage(scan.result.integrity),
          processTimeline: sanitizeForStorage(scan.result.processTimeline),
          exploreFiles: sanitizeForStorage(scan.result.exploreFiles),
          utilities: sanitizeForStorage(scan.result.utilities),
          windowsItems: sanitizeForStorage(scan.result.windowsItems),
          auditLog: sanitizeForStorage(scan.result.auditLog),
          loadedModules: sanitizeForStorage(scan.result.loadedModules),
          processHandles: sanitizeForStorage(scan.result.processHandles),
          services: sanitizeForStorage(scan.result.services),
          drivers: sanitizeForStorage(scan.result.drivers),
          persistenceItems: sanitizeForStorage(scan.result.persistenceItems),
          eventLogs: sanitizeForStorage(scan.result.eventLogs),
          defenderEvents: sanitizeForStorage(scan.result.defenderEvents),
          executionArtifacts: sanitizeForStorage(
            scan.result.executionArtifacts,
          ),
          fileTriage: sanitizeForStorage(scan.result.fileTriage),
          networkConnections: sanitizeForStorage(
            scan.result.networkConnections,
          ),
          dnsCache: sanitizeForStorage(scan.result.dnsCache),
          hostsEntries: sanitizeForStorage(scan.result.hostsEntries),
          forensicTimeline: sanitizeForStorage(scan.result.forensicTimeline),
          createdAt: scan.result.createdAt,
        }
      : null,
    modules: scan.modules.map((module) => ({
      id: module.id,
      moduleName: module.moduleName,
      status: module.status,
      durationMs: module.durationMs,
      errorCode: module.errorCode,
      errorMessage: module.errorMessage,
      createdAt: module.createdAt,
    })),
    evidence: scan.evidence.map((evidence) => ({
      id: evidence.id,
      clientEvidenceId: evidence.clientEvidenceId,
      type: evidence.type,
      title: evidence.title,
      data: sanitizeForStorage(evidence.data),
      storageRef: evidence.storageRef,
      createdAt: evidence.createdAt,
    })),
    launcherProfiles: scan.launcherProfiles.map((profile) => ({
      id: profile.id,
      profileName: profile.profileName,
      launcherType: profile.launcherType,
      version: profile.version,
      channel: profile.channel,
      pathMasked: profile.pathMasked,
      executableHash: profile.executableHash,
      publisher: profile.publisher,
      status: profile.status,
      tags: sanitizeForStorage(profile.tags),
      installTime: profile.installTime,
      updateTime: profile.updateTime,
      lastLaunchTime: profile.lastLaunchTime,
      metadata: sanitizeForStorage(profile.metadata),
      createdAt: profile.createdAt,
    })),
    clientModAssets: scan.clientModAssets.map((asset) => ({
      id: asset.id,
      name: asset.name,
      sourceLauncher: asset.sourceLauncher,
      pathMasked: asset.pathMasked,
      fileCount: asset.fileCount,
      totalSize: asset.totalSize?.toString() ?? null,
      createdTime: asset.createdTime,
      modifiedTime: asset.modifiedTime,
      status: asset.status,
      metadata: sanitizeForStorage(asset.metadata),
      createdAt: asset.createdAt,
    })),
    processTimes: scan.processTimes.map((processTime) => ({
      id: processTime.id,
      processName: processTime.processName,
      pathMasked: processTime.pathMasked,
      firstSeenAt: processTime.firstSeenAt,
      lastSeenAt: processTime.lastSeenAt,
      startedAt: processTime.startedAt,
      endedAt: processTime.endedAt,
      durationMs: processTime.durationMs,
      source: processTime.source,
      status: processTime.status,
      metadata: sanitizeForStorage(processTime.metadata),
      createdAt: processTime.createdAt,
    })),
    fileLogs: scan.fileLogs.map((fileLog) => ({
      id: fileLog.id,
      action: fileLog.action,
      pathMasked: fileLog.pathMasked,
      oldPathMasked: fileLog.oldPathMasked,
      newPathMasked: fileLog.newPathMasked,
      timestamp: fileLog.timestamp,
      source: fileLog.source,
      confidence: fileLog.confidence,
      relatedProcess: fileLog.relatedProcess,
      severity: fileLog.severity,
      metadata: sanitizeForStorage(fileLog.metadata),
      createdAt: fileLog.createdAt,
    })),
    aiReview: scan.aiReview
      ? {
          id: scan.aiReview.id,
          assessment: scan.aiReview.assessment,
          confidence: scan.aiReview.confidence,
          summaryForModerator: scan.aiReview.summaryForModerator,
          summaryForPlayer: scan.aiReview.summaryForPlayer,
          recommendedAction: scan.aiReview.recommendedAction,
          keyIndicators: sanitizeForStorage(scan.aiReview.keyIndicators),
          possibleFalsePositives: sanitizeForStorage(
            scan.aiReview.possibleFalsePositives,
          ),
          contradictions: sanitizeForStorage(scan.aiReview.contradictions),
          moderatorChecklist: sanitizeForStorage(
            scan.aiReview.moderatorChecklist,
          ),
          questionsForPlayer: sanitizeForStorage(
            scan.aiReview.questionsForPlayer,
          ),
          evidenceReferences: sanitizeForStorage(
            scan.aiReview.evidenceReferences,
          ),
          model: scan.aiReview.model,
          promptVersion: scan.aiReview.promptVersion,
          inputHash: scan.aiReview.inputHash,
          generatedAt: scan.aiReview.generatedAt,
          createdAt: scan.aiReview.createdAt,
          updatedAt: scan.aiReview.updatedAt,
          evidenceLinks: scan.aiReview.evidenceLinks.map((link) => ({
            id: link.id,
            findingId: link.findingId,
            evidenceId: link.evidenceId,
            finding: link.finding,
            evidence: link.evidence,
            createdAt: link.createdAt,
          })),
        }
      : null,
    automationEvents: scan.automationEvents.map((event) => ({
      id: event.id,
      eventType: event.eventType,
      idempotencyKey: event.idempotencyKey,
      status: event.status,
      attemptCount: event.attemptCount,
      lastError: event.lastError,
      lastAttemptAt: event.lastAttemptAt,
      createdAt: event.createdAt,
      updatedAt: event.updatedAt,
    })),
    auditLogs: auditLogs.map((entry) => ({
      id: entry.id,
      accountId: entry.accountId,
      actorUserId: entry.actorUserId,
      action: entry.action,
      entityType: entry.entityType,
      entityId: entry.entityId,
      before: sanitizeForStorage(entry.before),
      after: sanitizeForStorage(entry.after),
      createdAt: entry.createdAt,
    })),
    findings: scan.findings
      .filter((finding) => finding.sourceModule !== "scanner_phase1")
      .map(serializeFinding),
  };
}

function findingOrderBy(
  query: FindingQuery,
): Prisma.ScanFindingOrderByWithRelationInput {
  const direction = query.direction ?? "desc";

  if (query.sort === "severity") {
    return { severity: direction };
  }

  if (query.sort === "category") {
    return { category: direction };
  }

  if (query.sort === "title") {
    return { title: direction };
  }

  if (query.sort === "confidence") {
    return { confidence: direction };
  }

  return { createdAt: direction };
}

function escapeHtml(value: unknown) {
  let text = "";

  if (value && typeof value === "object") {
    text = JSON.stringify(value);
  } else if (typeof value === "string") {
    text = value;
  } else if (typeof value === "number" || typeof value === "boolean") {
    text = String(value);
  }

  return cleanForensicLabel(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function cleanForensicLabel(value: string) {
  return value
    .replace(/\bAF-[3-7]\s+review item:\s*/gi, "")
    .replace(/\bAF-[3-7]\b/gi, "Forensic");
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function htmlRows(rows: Array<[string, unknown]>) {
  return rows
    .map(
      ([label, value]) =>
        `<tr><th>${escapeHtml(label)}</th><td>${escapeHtml(value)}</td></tr>`,
    )
    .join("");
}

function renderList(items: unknown[], empty: string) {
  if (items.length === 0) {
    return `<p class="muted">${escapeHtml(empty)}</p>`;
  }

  return `<ul>${items
    .map((item) => {
      const row = asRecord(item);
      const title =
        row.title ?? row.moduleName ?? row.name ?? row.action ?? item;
      const detail = row.message ?? row.status ?? row.severity ?? "";

      return `<li><strong>${escapeHtml(title)}</strong> ${escapeHtml(detail)}</li>`;
    })
    .join("")}</ul>`;
}

function reportScanLabel(scan: { id?: unknown; playerLabel?: unknown }) {
  if (typeof scan.playerLabel === "string" && scan.playerLabel.trim() !== "") {
    return scan.playerLabel.trim();
  }

  const id =
    typeof scan.id === "string" && scan.id.length >= 8
      ? scan.id.slice(0, 8)
      : "unlabeled";

  return `Unlabeled scan - Scan ${id}`;
}

function sanitizeReportValue(value: unknown): unknown {
  if (value === undefined || value === null) {
    return null;
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (typeof value === "bigint") {
    return value.toString();
  }

  if (typeof value === "string") {
    return sanitizeForStorage(cleanForensicLabel(value));
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeReportValue(item));
  }

  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        sanitizeReportValue(item),
      ]),
    );
  }

  return "[UNSUPPORTED]";
}

function renderHtmlReport(report: unknown) {
  const root = asRecord(report);
  const scan = asRecord(root.scan);
  const result = asRecord(scan.result);
  const device = asRecord(scan.device);
  const deviceMark = asRecord(device.currentMark);
  const aiReview = asRecord(scan.aiReview);
  const findings = asArray(scan.findings);
  const modules = asArray(scan.modules);
  const evidence = asArray(scan.evidence);
  const auditLogs = asArray(scan.auditLogs);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>SideraScan Report ${escapeHtml(scan.id)}</title>
  <style>
    body { background: #0f1b2f; color: #e5eefc; font-family: Arial, sans-serif; margin: 32px; }
    h1, h2 { margin: 0 0 12px; }
    section { background: #172842; border: 1px solid rgba(255,255,255,.12); border-radius: 8px; margin: 16px 0; padding: 18px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border-bottom: 1px solid rgba(255,255,255,.1); padding: 8px; text-align: left; vertical-align: top; }
    th { color: #93c5fd; width: 220px; }
    .muted { color: #94a3b8; }
    li { margin: 7px 0; }
    @media print { body { background: white; color: #111827; } section { break-inside: avoid; border-color: #cbd5e1; } th { color: #1e40af; } }
  </style>
</head>
<body>
  <h1>SideraScan Report</h1>
  <p class="muted">Exported at ${escapeHtml(root.exportedAt)}. Sensitive fields are redacted.</p>
  <section>
    <h2>Overview</h2>
    <table><tbody>${htmlRows([
      ["Scan ID", scan.id],
      ["Account", scan.accountName],
      ["Player", reportScanLabel(scan)],
      ["Status", scan.status],
      ["Risk Score", scan.riskScore],
      ["Max Severity", scan.maxSeverity],
      ["Scanner", scan.scannerVersion],
      ["Created", scan.createdAt],
      ["Finished", scan.finishedAt ?? "Not finished"],
      ["Payload Hash", result.payloadHash ?? "Unavailable"],
    ])}</tbody></table>
  </section>
  <section>
    <h2>Device / HWID</h2>
    <table><tbody>${htmlRows([
      ["Fingerprint Prefix", device.fingerprintPrefix ?? "Unavailable"],
      ["Confidence", device.fingerprintConfidence ?? "Unavailable"],
      ["Current Mark", deviceMark.status ?? "None"],
      ["Mark Reason", deviceMark.reason ?? "None"],
    ])}</tbody></table>
  </section>
  <section>
    <h2>Indication Log</h2>
    ${renderList(findings, "No findings were recorded.")}
  </section>
  <section>
    <h2>Module Status</h2>
    ${renderList(modules, "No module status rows were recorded.")}
  </section>
  <section>
    <h2>Evidence References</h2>
    ${renderList(evidence, "No evidence references were recorded.")}
  </section>
  <section>
    <h2>AI Review</h2>
    <table><tbody>${htmlRows([
      ["Assessment", aiReview.assessment ?? "Unavailable"],
      ["Confidence", aiReview.confidence ?? "Unavailable"],
      ["Recommended Action", aiReview.recommendedAction ?? "Unavailable"],
      ["Summary", aiReview.summaryForModerator ?? "Unavailable"],
      ["Model", aiReview.model ?? "Unavailable"],
      ["Generated At", aiReview.generatedAt ?? "Unavailable"],
    ])}</tbody></table>
  </section>
  <section>
    <h2>Audit Summary</h2>
    ${renderList(auditLogs, "No audit rows were attached to this report.")}
  </section>
</body>
</html>`;
}

@Injectable()
export class ScansService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly monitoring: MonitoringService,
  ) {}

  async canRetryAiReview(viewer: AuthUser, scanId: string) {
    const scan = await this.prisma.scanSession.findFirst({
      where: {
        id: scanId,
        account: visibleAccountWhere(viewer),
      },
      include: {
        account: {
          select: {
            memberships: {
              where: { userId: viewer.id },
              select: { role: true },
            },
          },
        },
      },
    });

    if (!scan) {
      throw new NotFoundException("Scan not found");
    }

    return (
      viewer.globalRole === GlobalRole.SUPER_ADMIN ||
      scan.account.memberships[0]?.role === AccountRole.ACCOUNT_OWNER
    );
  }

  async updateScan(
    viewer: AuthUser,
    scanId: string,
    input: { playerLabel?: string | null },
    sourceIp?: string,
  ) {
    const scan = await this.prisma.scanSession.findFirst({
      where: {
        id: scanId,
        account: visibleAccountWhere(viewer),
      },
      include: {
        account: {
          select: {
            memberships: {
              where: { userId: viewer.id },
              select: { role: true },
            },
          },
        },
      },
    });

    if (!scan) {
      throw new NotFoundException("Scan not found");
    }

    const role = scan.account.memberships[0]?.role ?? null;
    const canEdit =
      viewer.globalRole === GlobalRole.SUPER_ADMIN ||
      role === AccountRole.ACCOUNT_OWNER ||
      role === AccountRole.MODERATOR;

    if (!canEdit) {
      await this.monitoring.recordSecurityEvent({
        accountId: scan.accountId,
        eventType: "PERMISSION_DENIED",
        message: "Scan label update denied.",
        metadata: { scanId },
        severity: MonitoringSeverity.WARNING,
        sourceIp,
      });
      throw new ForbiddenException("Insufficient scan permissions");
    }

    const nextPlayerLabel =
      input.playerLabel && input.playerLabel.trim() !== ""
        ? input.playerLabel.trim()
        : null;

    const updated = await this.prisma.scanSession.update({
      where: { id: scan.id },
      data: { playerLabel: nextPlayerLabel },
      include: scanDetailInclude,
    });

    await this.audit.log({
      accountId: scan.accountId,
      actorUserId: viewer.id,
      action: "SCAN_LABEL_UPDATED",
      entityType: "scan_session",
      entityId: scan.id,
      before: { playerLabel: scan.playerLabel },
      after: { playerLabel: nextPlayerLabel },
      sourceIp,
    });

    const auditLogs = await this.prisma.auditLog.findMany({
      where: {
        accountId: updated.accountId,
        OR: [
          { entityId: updated.id },
          { entityId: updated.result?.id ?? "" },
          { entityType: "scan_session", entityId: updated.id },
        ],
      },
      orderBy: { createdAt: "desc" },
      take: 50,
    });

    return serializeScanDetail(updated, auditLogs);
  }

  async listScans(viewer: AuthUser) {
    const scans = await this.prisma.scanSession.findMany({
      where: {
        account: visibleAccountWhere(viewer),
      },
      include: scanListInclude,
      orderBy: { createdAt: "desc" },
    });

    return scans.map(serializeScanListItem);
  }

  async getScan(viewer: AuthUser, scanId: string) {
    const scan = await this.prisma.scanSession.findFirst({
      where: {
        id: scanId,
        account: visibleAccountWhere(viewer),
      },
      include: scanDetailInclude,
    });

    if (!scan) {
      throw new NotFoundException("Scan not found");
    }

    const auditLogs = await this.prisma.auditLog.findMany({
      where: {
        accountId: scan.accountId,
        OR: [
          { entityId: scan.id },
          { entityId: scan.result?.id ?? "" },
          { entityType: "scan_session", entityId: scan.id },
        ],
      },
      orderBy: { createdAt: "desc" },
      take: 50,
    });

    return serializeScanDetail(scan, auditLogs);
  }

  async listFindings(viewer: AuthUser, scanId: string, query: FindingQuery) {
    const scan = await this.prisma.scanSession.findFirst({
      where: {
        id: scanId,
        account: visibleAccountWhere(viewer),
      },
      select: { id: true, accountId: true },
    });

    if (!scan) {
      throw new NotFoundException("Scan not found");
    }

    const page = Math.max(1, query.page ?? 1);
    const pageSize = Math.min(100, Math.max(1, query.pageSize ?? 20));
    const where: Prisma.ScanFindingWhereInput = {
      scanSessionId: scan.id,
      accountId: scan.accountId,
    };

    if (query.severity) {
      where.severity = query.severity;
    }

    if (query.category) {
      where.category = query.category;
    }

    if (query.q) {
      where.OR = [
        { title: { contains: query.q, mode: "insensitive" } },
        { message: { contains: query.q, mode: "insensitive" } },
        { sourceModule: { contains: query.q, mode: "insensitive" } },
      ];
    }

    const [items, total] = await this.prisma.$transaction([
      this.prisma.scanFinding.findMany({
        where,
        include: {
          evidence: { select: { id: true, type: true, title: true } },
        },
        orderBy: findingOrderBy(query),
        skip: (page - 1) * pageSize,
        take: pageSize,
      }),
      this.prisma.scanFinding.count({ where }),
    ]);

    return {
      items: items.map(serializeFinding),
      total,
      page,
      pageSize,
      totalPages: Math.max(1, Math.ceil(total / pageSize)),
    };
  }

  async exportScanReport(
    viewer: AuthUser,
    scanId: string,
    format: "html" | "json",
    sourceIp?: string,
  ) {
    const scan = await this.prisma.scanSession.findFirst({
      where: {
        id: scanId,
        account: visibleAccountWhere(viewer),
      },
      include: scanDetailInclude,
    });

    if (!scan) {
      throw new NotFoundException("Scan not found");
    }

    await this.ensureCanExportScan(viewer, scan.accountId, scan.id, sourceIp);

    const auditLogs = await this.prisma.auditLog.findMany({
      where: {
        accountId: scan.accountId,
        OR: [
          { entityId: scan.id },
          { entityId: scan.result?.id ?? "" },
          { entityType: "scan_session", entityId: scan.id },
        ],
      },
      orderBy: { createdAt: "desc" },
      take: 50,
    });
    const detail = serializeScanDetail(scan, auditLogs);
    const safeDetail: Record<string, unknown> = {
      ...detail,
      keyPrefix: detail.scannerKeyPrefix,
    };

    delete safeDetail.scannerKeyId;
    delete safeDetail.scannerKeyName;
    delete safeDetail.scannerKeyPrefix;
    safeDetail.findings = detail.findings.slice(
      0,
      env.REPORT_EXPORT_MAX_FINDINGS,
    );

    const report = sanitizeReportValue({
      exportedAt: new Date(),
      exportVersion: "phase-11-html-json-v1",
      scan: safeDetail,
      safety: {
        redacted: true,
        excludes: [
          "dashboard credentials",
          "scanner operational secrets",
          "upload challenge secrets",
          "full device fingerprint",
          "raw hardware identifiers",
          "raw AI prompt",
          "private unmasked paths",
        ],
      },
    });
    const fileStem = `siderascan-report-${scan.id}`;

    await this.audit.log({
      accountId: scan.accountId,
      actorUserId: viewer.id,
      action: "SCAN_REPORT_EXPORTED",
      entityType: "scan_session",
      entityId: scan.id,
      after: { format, findingCount: detail.findings.length },
      sourceIp,
    });

    if (format === "json") {
      return {
        body: JSON.stringify(report, null, 2),
        contentType: "application/json; charset=utf-8",
        fileName: `${fileStem}.json`,
      };
    }

    return {
      body: renderHtmlReport(report),
      contentType: "text/html; charset=utf-8",
      fileName: `${fileStem}.html`,
    };
  }

  private async ensureCanExportScan(
    viewer: AuthUser,
    accountId: string,
    scanId: string,
    sourceIp?: string,
  ) {
    if (viewer.globalRole === GlobalRole.SUPER_ADMIN) {
      return;
    }

    const membership = await this.prisma.userAccount.findUnique({
      where: {
        userId_accountId: {
          userId: viewer.id,
          accountId,
        },
      },
      select: { role: true },
    });

    if (
      membership?.role === AccountRole.ACCOUNT_OWNER ||
      membership?.role === AccountRole.MODERATOR
    ) {
      return;
    }

    await this.monitoring.recordSecurityEvent({
      accountId,
      actorUserId: viewer.id,
      eventType: "PERMISSION_DENIED",
      message: "User attempted to export a scan report without permission.",
      metadata: { scanId, accountId, role: membership?.role ?? null },
      severity: MonitoringSeverity.WARNING,
      sourceIp,
    });

    throw new ForbiddenException("Export permission required");
  }
}
