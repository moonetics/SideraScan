import { ForbiddenException, Injectable, NotFoundException } from "@nestjs/common";
import {
  AlertNotificationStatus,
  AutomationEventStatus,
  GlobalRole,
  MonitoringSeverity,
  Prisma,
  ScanReviewStatus,
  ScanStatus
} from "@prisma/client";
import type { AuthUser } from "../auth/auth.types";
import { sanitizeForStorage } from "../common/data-sanitizer";
import { env } from "../config/env";
import { PrismaService } from "../prisma/prisma.service";
import { bodyToSignedString, signN8nPayload } from "../scan-reviews/scan-review-signature";

type EventInput = {
  accountId?: string | null;
  actorUserId?: string | null;
  eventType: string;
  message: string;
  metadata?: unknown;
  service?: string;
  severity: MonitoringSeverity;
  sourceIp?: string | null;
};

type ListQuery = {
  eventType?: string;
  page?: number;
  pageSize?: number;
  q?: string;
  severity?: MonitoringSeverity;
  status?: AlertNotificationStatus;
};

function pageParams(query: ListQuery) {
  const page = Math.max(1, query.page ?? 1);
  const pageSize = Math.min(100, Math.max(1, query.pageSize ?? 20));

  return { page, pageSize };
}

function startOfToday() {
  const value = new Date();
  value.setHours(0, 0, 0, 0);

  return value;
}

function highEnoughForAlert(severity: MonitoringSeverity) {
  return (
    severity === MonitoringSeverity.HIGH ||
    severity === MonitoringSeverity.CRITICAL
  );
}

@Injectable()
export class MonitoringService {
  constructor(private readonly prisma: PrismaService) {}

  async recordMonitoringEvent(input: Omit<EventInput, "sourceIp" | "actorUserId">) {
    return this.prisma.monitoringEvent.create({
      data: {
        service: input.service ?? "api",
        eventType: input.eventType,
        severity: input.severity,
        message: input.message,
        metadata: sanitizeForStorage(input.metadata)
      }
    });
  }

  async recordSecurityEvent(input: EventInput) {
    const event = await this.prisma.securityEvent.create({
      data: {
        accountId: input.accountId ?? null,
        actorUserId: input.actorUserId ?? null,
        eventType: input.eventType,
        severity: input.severity,
        sourceIp: input.sourceIp ?? null,
        message: input.message,
        metadata: sanitizeForStorage(input.metadata)
      }
    });

    if (highEnoughForAlert(input.severity)) {
      await this.createAndDispatchAlert(event.id, input.service ?? "security");
    }

    return event;
  }

  async overview(viewer: AuthUser, sourceIp?: string) {
    await this.ensureSuperAdmin(viewer, "GET /monitoring/overview", sourceIp);
    const today = startOfToday();
    const [
      database,
      scansCompletedToday,
      failedScansToday,
      scannerUploadsToday,
      uploadAuthFailuresToday,
      pendingAiReviews,
      failedAiReviews,
      latestAutomationEvent,
      n8nFailedEvents,
      securityAlertsOpen,
      bannedHwidMatchesToday,
      alertFailures
    ] = await Promise.all([
      this.checkDatabase(),
      this.prisma.scanSession.count({
        where: { status: ScanStatus.COMPLETED, finishedAt: { gte: today } }
      }),
      this.prisma.scanSession.count({
        where: { status: ScanStatus.FAILED, updatedAt: { gte: today } }
      }),
      this.prisma.scanResult.count({ where: { createdAt: { gte: today } } }),
      this.prisma.securityEvent.count({
        where: {
          eventType: "SCANNER_UPLOAD_AUTH_FAILED",
          createdAt: { gte: today }
        }
      }),
      this.prisma.scanSession.count({
        where: { reviewStatus: ScanReviewStatus.PENDING }
      }),
      this.prisma.scanSession.count({
        where: { reviewStatus: ScanReviewStatus.FAILED }
      }),
      this.prisma.automationEvent.findFirst({
        orderBy: { updatedAt: "desc" },
        select: {
          eventType: true,
          status: true,
          attemptCount: true,
          lastError: true,
          updatedAt: true
        }
      }),
      this.prisma.automationEvent.count({
        where: { status: AutomationEventStatus.FAILED }
      }),
      this.prisma.securityEvent.count({
        where: {
          severity: {
            in: [MonitoringSeverity.HIGH, MonitoringSeverity.CRITICAL]
          },
          createdAt: { gte: today }
        }
      }),
      this.prisma.securityEvent.count({
        where: {
          eventType: "BANNED_HWID_MATCH",
          createdAt: { gte: today }
        }
      }),
      this.prisma.alertNotification.count({
        where: { status: AlertNotificationStatus.FAILED }
      })
    ]);
    const failedUploadsToday = failedScansToday + uploadAuthFailuresToday;
    const uploadErrorRate =
      scannerUploadsToday + failedUploadsToday === 0
        ? 0
        : Math.round(
            (failedUploadsToday / (scannerUploadsToday + failedUploadsToday)) *
              100
          );

    return {
      health: {
        api: "ok",
        database,
        n8n:
          latestAutomationEvent?.status === AutomationEventStatus.FAILED ||
          alertFailures > 0
            ? "error"
            : "ok",
        ai:
          failedAiReviews > 0
            ? "error"
            : pendingAiReviews > 0
              ? "pending"
              : "ok"
      },
      scannerUploads: {
        uploadsToday: scannerUploadsToday,
        failedUploadsToday,
        uploadAuthFailuresToday,
        uploadErrorRate
      },
      scans: {
        completedToday: scansCompletedToday,
        failedToday: failedScansToday
      },
      n8n: {
        latestEvent: latestAutomationEvent,
        failedEvents: n8nFailedEvents
      },
      aiReviews: {
        pending: pendingAiReviews,
        failed: failedAiReviews
      },
      security: {
        highOrCriticalToday: securityAlertsOpen,
        bannedHwidMatchesToday
      },
      alerts: {
        failed: alertFailures
      }
    };
  }

  async listSecurityEvents(
    viewer: AuthUser,
    query: ListQuery,
    sourceIp?: string
  ) {
    await this.ensureSuperAdmin(
      viewer,
      "GET /monitoring/security-events",
      sourceIp
    );
    const { page, pageSize } = pageParams(query);
    const where: Prisma.SecurityEventWhereInput = {};

    if (query.eventType) {
      where.eventType = query.eventType;
    }

    if (query.severity) {
      where.severity = query.severity;
    }

    if (query.q) {
      where.OR = [
        { eventType: { contains: query.q, mode: "insensitive" } },
        { message: { contains: query.q, mode: "insensitive" } },
        { sourceIp: { contains: query.q, mode: "insensitive" } }
      ];
    }

    const [items, total] = await this.prisma.$transaction([
      this.prisma.securityEvent.findMany({
        where,
        include: { account: { select: { id: true, name: true } } },
        orderBy: { createdAt: "desc" },
        skip: (page - 1) * pageSize,
        take: pageSize
      }),
      this.prisma.securityEvent.count({ where })
    ]);

    return {
      items: items.map((event) => ({
        id: event.id,
        accountId: event.accountId,
        accountName: event.account?.name ?? null,
        actorUserId: event.actorUserId,
        eventType: event.eventType,
        severity: event.severity,
        sourceIp: event.sourceIp,
        message: event.message,
        metadata: sanitizeForStorage(event.metadata),
        createdAt: event.createdAt
      })),
      total,
      page,
      pageSize,
      totalPages: Math.max(1, Math.ceil(total / pageSize))
    };
  }

  async listAlerts(viewer: AuthUser, query: ListQuery, sourceIp?: string) {
    await this.ensureSuperAdmin(viewer, "GET /monitoring/alerts", sourceIp);
    const { page, pageSize } = pageParams(query);
    const where: Prisma.AlertNotificationWhereInput = {};

    if (query.eventType) {
      where.eventType = query.eventType;
    }

    if (query.severity) {
      where.severity = query.severity;
    }

    if (query.status) {
      where.status = query.status;
    }

    if (query.q) {
      where.OR = [
        { eventType: { contains: query.q, mode: "insensitive" } },
        { service: { contains: query.q, mode: "insensitive" } },
        { lastError: { contains: query.q, mode: "insensitive" } }
      ];
    }

    const [items, total] = await this.prisma.$transaction([
      this.prisma.alertNotification.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip: (page - 1) * pageSize,
        take: pageSize
      }),
      this.prisma.alertNotification.count({ where })
    ]);

    return {
      items: items.map((alert) => ({
        id: alert.id,
        securityEventId: alert.securityEventId,
        channel: alert.channel,
        status: alert.status,
        severity: alert.severity,
        service: alert.service,
        eventType: alert.eventType,
        idempotencyKey: alert.idempotencyKey,
        payloadRedacted: sanitizeForStorage(alert.payloadRedacted),
        attemptCount: alert.attemptCount,
        lastError: alert.lastError,
        lastAttemptAt: alert.lastAttemptAt,
        createdAt: alert.createdAt,
        updatedAt: alert.updatedAt
      })),
      total,
      page,
      pageSize,
      totalPages: Math.max(1, Math.ceil(total / pageSize))
    };
  }

  async retryAlert(viewer: AuthUser, alertId: string, sourceIp?: string) {
    await this.ensureSuperAdmin(
      viewer,
      "POST /monitoring/alerts/:id/retry",
      sourceIp
    );
    const alert = await this.dispatchAlert(alertId, true);

    return {
      status: alert.status,
      alertId: alert.id,
      attemptCount: alert.attemptCount
    };
  }

  private async createAndDispatchAlert(securityEventId: string, service: string) {
    const securityEvent = await this.prisma.securityEvent.findUnique({
      where: { id: securityEventId }
    });

    if (!securityEvent) {
      return null;
    }

    const payload = sanitizeForStorage({
      event: "security.alert",
      severity: securityEvent.severity,
      service,
      eventType: securityEvent.eventType,
      message: securityEvent.message,
      dashboardUrl: `${env.APP_DASHBOARD_URL}/monitoring`,
      createdAt: securityEvent.createdAt,
      metadata: securityEvent.metadata
    });
    const alert = await this.prisma.alertNotification.upsert({
      where: {
        idempotencyKey: `security.alert:${securityEvent.id}:n8n`
      },
      create: {
        securityEventId: securityEvent.id,
        channel: "N8N",
        status: AlertNotificationStatus.PENDING,
        severity: securityEvent.severity,
        service,
        eventType: securityEvent.eventType,
        idempotencyKey: `security.alert:${securityEvent.id}:n8n`,
        payloadRedacted: payload
      },
      update: {
        status: AlertNotificationStatus.PENDING,
        lastError: null,
        payloadRedacted: payload
      }
    });

    return this.dispatchAlert(alert.id);
  }

  private async dispatchAlert(alertId: string, force = false) {
    const alert = await this.prisma.alertNotification.findUnique({
      where: { id: alertId }
    });

    if (!alert) {
      throw new NotFoundException("Alert not found");
    }

    if (!env.N8N_ALERT_WEBHOOK_ENABLED) {
      return this.prisma.alertNotification.update({
        where: { id: alert.id },
        data: {
          status: AlertNotificationStatus.DISABLED,
          lastError: "n8n alert webhook disabled",
          lastAttemptAt: new Date()
        }
      });
    }

    if (!env.N8N_ALERT_WEBHOOK_URL) {
      return this.failAlert(alert.id, "N8N_ALERT_WEBHOOK_URL is not configured");
    }

    if (!force && alert.attemptCount >= env.N8N_ALERT_MAX_ATTEMPTS) {
      return alert;
    }

    const timestamp = Math.floor(Date.now() / 1000).toString();
    const body = bodyToSignedString(alert.payloadRedacted);
    const signature = signN8nPayload(timestamp, body);

    try {
      const response = await fetch(env.N8N_ALERT_WEBHOOK_URL, {
        body,
        headers: {
          "content-type": "application/json",
          "x-idempotency-key": alert.idempotencyKey,
          "x-siderascan-event": "security.alert",
          "x-siderascan-signature": signature,
          "x-siderascan-timestamp": timestamp
        },
        method: "POST"
      });

      if (!response.ok) {
        throw new Error(`n8n alert responded with status ${response.status}`);
      }

      return this.prisma.alertNotification.update({
        where: { id: alert.id },
        data: {
          status: AlertNotificationStatus.SENT,
          attemptCount: { increment: 1 },
          lastError: null,
          lastAttemptAt: new Date()
        }
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "n8n alert request failed";

      return this.failAlert(alert.id, message);
    }
  }

  private async failAlert(alertId: string, message: string) {
    return this.prisma.alertNotification.update({
      where: { id: alertId },
      data: {
        status: AlertNotificationStatus.FAILED,
        attemptCount: { increment: 1 },
        lastError: message,
        lastAttemptAt: new Date()
      }
    });
  }

  private async checkDatabase(): Promise<"ok" | "error"> {
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      return "ok";
    } catch {
      return "error";
    }
  }

  private async ensureSuperAdmin(
    viewer: AuthUser,
    route: string,
    sourceIp?: string
  ) {
    if (viewer.globalRole === GlobalRole.SUPER_ADMIN) {
      return;
    }

    await this.recordSecurityEvent({
      actorUserId: viewer.id,
      eventType: "PERMISSION_DENIED",
      message: "Non-Super Admin attempted to access monitoring.",
      metadata: { route, userId: viewer.id },
      severity: MonitoringSeverity.WARNING,
      sourceIp
    });

    throw new ForbiddenException("Super Admin access required");
  }
}
