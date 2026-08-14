import { ForbiddenException, Injectable } from "@nestjs/common";
import { GlobalRole, MonitoringSeverity, Prisma } from "@prisma/client";
import { AuditService } from "../audit/audit.service";
import type { AuthUser } from "../auth/auth.types";
import { env } from "../config/env";
import { MonitoringService } from "../monitoring/monitoring.service";
import { PrismaService } from "../prisma/prisma.service";

type RetentionInput = {
  scanResultsDays?: number;
  findingsEvidenceDays?: number;
  screenshotsDays?: number;
  detectionSamplesDays?: number;
  monitoringEventsDays?: number;
  securityEventsDays?: number;
  auditLogsDays?: number;
};

const settingId = "global";

function defaultRetentionData() {
  return {
    id: settingId,
    scanResultsDays: env.RETENTION_SCAN_RESULTS_DAYS,
    findingsEvidenceDays: env.RETENTION_FINDINGS_EVIDENCE_DAYS,
    screenshotsDays: env.RETENTION_SCREENSHOTS_DAYS,
    detectionSamplesDays: env.RETENTION_DETECTION_SAMPLES_DAYS,
    monitoringEventsDays: env.RETENTION_MONITORING_EVENTS_DAYS,
    securityEventsDays: env.RETENTION_SECURITY_EVENTS_DAYS,
    auditLogsDays: env.RETENTION_AUDIT_LOGS_DAYS
  };
}

function cutoff(days: number) {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000);
}

function serializeRetention(
  setting: Prisma.RetentionSettingGetPayload<Record<string, never>>
) {
  return {
    id: setting.id,
    scanResultsDays: setting.scanResultsDays,
    findingsEvidenceDays: setting.findingsEvidenceDays,
    screenshotsDays: setting.screenshotsDays,
    detectionSamplesDays: setting.detectionSamplesDays,
    monitoringEventsDays: setting.monitoringEventsDays,
    securityEventsDays: setting.securityEventsDays,
    auditLogsDays: setting.auditLogsDays,
    updatedById: setting.updatedById,
    createdAt: setting.createdAt,
    updatedAt: setting.updatedAt
  };
}

@Injectable()
export class SettingsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly monitoring: MonitoringService
  ) {}

  async getRetention(viewer: AuthUser, sourceIp?: string) {
    await this.ensureSuperAdmin(viewer, "GET /settings/retention", sourceIp);
    const setting = await this.ensureRetentionSetting();

    return serializeRetention(setting);
  }

  async updateRetention(
    viewer: AuthUser,
    input: RetentionInput,
    sourceIp?: string
  ) {
    await this.ensureSuperAdmin(viewer, "PATCH /settings/retention", sourceIp);
    const before = await this.ensureRetentionSetting();
    const after = await this.prisma.retentionSetting.update({
      where: { id: settingId },
      data: {
        ...input,
        updatedById: viewer.id
      }
    });

    await this.audit.log({
      actorUserId: viewer.id,
      action: "RETENTION_SETTINGS_UPDATED",
      entityType: "retention_settings",
      entityId: settingId,
      before: serializeRetention(before),
      after: serializeRetention(after),
      sourceIp
    });

    return serializeRetention(after);
  }

  async retentionDryRun(viewer: AuthUser, sourceIp?: string) {
    await this.ensureSuperAdmin(
      viewer,
      "POST /settings/retention/dry-run",
      sourceIp
    );
    const setting = await this.ensureRetentionSetting();
    const scanResultCutoff = cutoff(setting.scanResultsDays);
    const findingCutoff = cutoff(setting.findingsEvidenceDays);
    const screenshotCutoff = cutoff(setting.screenshotsDays);
    const sampleCutoff = cutoff(setting.detectionSamplesDays);
    const monitoringCutoff = cutoff(setting.monitoringEventsDays);
    const securityCutoff = cutoff(setting.securityEventsDays);
    const auditCutoff = cutoff(setting.auditLogsDays);
    const [
      scanResults,
      scanFindings,
      scanEvidence,
      screenshots,
      detectionSamples,
      detectionSampleStrings,
      monitoringEvents,
      securityEvents,
      auditLogs
    ] = await Promise.all([
      this.prisma.scanResult.count({ where: { createdAt: { lt: scanResultCutoff } } }),
      this.prisma.scanFinding.count({ where: { createdAt: { lt: findingCutoff } } }),
      this.prisma.scanEvidence.count({ where: { createdAt: { lt: findingCutoff } } }),
      this.prisma.scanEvidence.count({
        where: {
          createdAt: { lt: screenshotCutoff },
          OR: [
            { type: { equals: "screenshot", mode: "insensitive" } },
            { storageRef: { not: null } }
          ]
        }
      }),
      this.prisma.detectionSample.count({
        where: { createdAt: { lt: sampleCutoff } }
      }),
      this.prisma.detectionSampleString.count({
        where: { createdAt: { lt: sampleCutoff } }
      }),
      this.prisma.monitoringEvent.count({
        where: { createdAt: { lt: monitoringCutoff } }
      }),
      this.prisma.securityEvent.count({
        where: { createdAt: { lt: securityCutoff } }
      }),
      this.prisma.auditLog.count({ where: { createdAt: { lt: auditCutoff } } })
    ]);

    await this.audit.log({
      actorUserId: viewer.id,
      action: "RETENTION_DRY_RUN",
      entityType: "retention_settings",
      entityId: settingId,
      after: {
        scanResults,
        scanFindings,
        scanEvidence,
        screenshots,
        detectionSamples,
        detectionSampleStrings,
        monitoringEvents,
        securityEvents,
        auditLogs
      },
      sourceIp
    });

    return {
      generatedAt: new Date(),
      policy: serializeRetention(setting),
      candidates: {
        scanResults,
        scanFindings,
        scanEvidence,
        screenshots,
        detectionSamples,
        detectionSampleStrings,
        monitoringEvents,
        securityEvents,
        auditLogs
      },
      deletesRecords: false
    };
  }

  private ensureRetentionSetting() {
    return this.prisma.retentionSetting.upsert({
      where: { id: settingId },
      create: defaultRetentionData(),
      update: {}
    });
  }

  private async ensureSuperAdmin(
    viewer: AuthUser,
    route: string,
    sourceIp?: string
  ) {
    if (viewer.globalRole === GlobalRole.SUPER_ADMIN) {
      return;
    }

    await this.monitoring.recordSecurityEvent({
      actorUserId: viewer.id,
      eventType: "PERMISSION_DENIED",
      message: "Non-Super Admin attempted to access production settings.",
      metadata: { route, userId: viewer.id },
      severity: MonitoringSeverity.WARNING,
      sourceIp
    });

    throw new ForbiddenException("Super Admin access required");
  }
}
