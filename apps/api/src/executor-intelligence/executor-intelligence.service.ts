import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  OnApplicationBootstrap,
  OnApplicationShutdown
} from "@nestjs/common";
import {
  DetectionRuleScope,
  DetectionRuleType,
  FindingCategory,
  MonitoringSeverity,
  Prisma,
  Severity
} from "@prisma/client";
import { AuditService } from "../audit/audit.service";
import { isSuperAdmin } from "../auth/authz";
import type { AuthUser } from "../auth/auth.types";
import { sanitizeForStorage, sanitizeText } from "../common/data-sanitizer";
import { env } from "../config/env";
import { MonitoringService } from "../monitoring/monitoring.service";
import { PrismaService } from "../prisma/prisma.service";

const SETTINGS_ID = "global";
const MANAGED_BY = "EXECUTOR_INTELLIGENCE";
const ATTRIBUTION = "Executors.Online / WhatExpsAre.Online";
const GENERIC_TOKENS = new Set([
  "real",
  "wave",
  "severe",
  "photon",
  "lumen",
  "cosmic",
  "velocity",
  "volt"
]);

type FeedItem = {
  title: string;
  slug?: unknown;
  platform?: string;
  extype?: string;
  type?: string;
  detected?: boolean;
  updateStatus?: boolean;
  version?: string;
  updatedDate?: string;
  websitelink?: string;
  hidden?: boolean;
};

type UpdateSettingsInput = {
  enabled?: boolean;
  sourceUrl?: string;
  fallbackUrl?: string;
  cacheTtlSeconds?: number;
};

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function slugFromUnknown(value: unknown, fallback: string) {
  if (typeof value === "string") {
    return normalizeToken(value);
  }
  if (isObject(value) && typeof value.slug === "string") {
    return normalizeToken(value.slug);
  }

  return normalizeToken(fallback);
}

function normalizeToken(value: string) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 160);
}

function compactAlias(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function safeHost(value?: string) {
  if (!value) {
    return null;
  }
  try {
    const host = new URL(value).hostname
      .toLowerCase()
      .replace(/^www\./, "")
      .slice(0, 160);

    return host || null;
  } catch {
    return null;
  }
}

function isWindowsPlatform(value?: string) {
  return Boolean(value?.toLowerCase().includes("windows"));
}

function safeItem(item: FeedItem, sourceName: string, sourceUrl: string) {
  const title = sanitizeText(String(item.title ?? "").trim()).slice(0, 160);
  const slug = slugFromUnknown(item.slug, title);
  const websiteHost = safeHost(item.websitelink);

  return {
    title,
    slug,
    platform: sanitizeText(String(item.platform ?? "unknown")).slice(0, 80),
    extype: item.extype ?? item.type ?? null,
    detected: Boolean(item.detected),
    updateStatus: Boolean(item.updateStatus),
    version: item.version ? sanitizeText(item.version).slice(0, 120) : null,
    updatedDateText: item.updatedDate
      ? sanitizeText(item.updatedDate).slice(0, 160)
      : null,
    websiteHost,
    sourceName,
    sourceUrl,
    sourceMetadata: sanitizeForStorage({
      attribution: ATTRIBUTION,
      hidden: Boolean(item.hidden)
    })
  };
}

function processAliases(title: string, slug: string) {
  const values = new Set<string>();
  for (const item of [title, slug, compactAlias(title), compactAlias(slug)]) {
    const cleaned = item.trim();
    if (cleaned.length >= 3) {
      values.add(`${cleaned}.exe`);
    }
  }

  return Array.from(values).slice(0, 8);
}

function pathPatterns(title: string, slug: string, websiteHost: string | null) {
  const tokens = new Set<string>();
  for (const item of [slug, compactAlias(title), compactAlias(slug)]) {
    if (item.length >= 5 && !GENERIC_TOKENS.has(item)) {
      tokens.add(item);
    }
  }
  if (websiteHost) {
    const hostToken = websiteHost.split(".")[0] ?? "";
    if (hostToken.length >= 5 && !GENERIC_TOKENS.has(hostToken)) {
      tokens.add(hostToken);
    }
  }

  return Array.from(tokens)
    .slice(0, 4)
    .map((token) => `(?i)(^|[\\\\/_. -])${token}([\\\\/_. -]|$)`);
}

@Injectable()
export class ExecutorIntelligenceService
  implements OnApplicationBootstrap, OnApplicationShutdown
{
  private interval?: ReturnType<typeof setInterval>;
  private startupTimer?: ReturnType<typeof setTimeout>;
  private syncInFlight = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly monitoring: MonitoringService
  ) {}

  onApplicationBootstrap() {
    if (!env.EXECUTOR_INTEL_AUTO_SYNC_ENABLED) {
      return;
    }

    const run = () => {
      void this.syncFromScheduler();
    };
    this.startupTimer = setTimeout(run, 30_000);
    this.interval = setInterval(
      run,
      env.EXECUTOR_INTEL_AUTO_SYNC_INTERVAL_SECONDS * 1000
    );
  }

  onApplicationShutdown() {
    if (this.startupTimer) {
      clearTimeout(this.startupTimer);
    }
    if (this.interval) {
      clearInterval(this.interval);
    }
  }

  async getOverview(viewer: AuthUser, sourceIp?: string, syncStatus?: string) {
    await this.ensureSuperAdmin(viewer, "GET /executor-intelligence", sourceIp);
    const settings = await this.ensureSettings();
    const [items, itemCount, windowsItemCount, generatedRuleCount] =
      await Promise.all([
        this.prisma.executorIntelligenceItem.findMany({
          orderBy: [{ updateStatus: "desc" }, { title: "asc" }],
          take: 100
        }),
        this.prisma.executorIntelligenceItem.count(),
        this.prisma.executorIntelligenceItem.count({
          where: { platform: { contains: "Windows", mode: "insensitive" } }
        }),
        this.prisma.detectionRule.count({
          where: { managedBy: MANAGED_BY, deletedAt: null }
        })
      ]);

    return {
      settings: this.serializeSettings(settings),
      counts: {
        items: itemCount,
        windowsItems: windowsItemCount,
        generatedRules: generatedRuleCount
      },
      syncStatus,
      attribution: settings.attribution,
      items: items.map((item) => ({
        id: item.id,
        title: item.title,
        slug: item.slug,
        platform: item.platform,
        extype: item.extype,
        detected: item.detected,
        updateStatus: item.updateStatus,
        version: item.version,
        updatedDateText: item.updatedDateText,
        websiteHost: item.websiteHost,
        enabled: item.enabled,
        sourceName: item.sourceName,
        generatedRuleIds: sanitizeForStorage(item.generatedRuleIds),
        lastSeenAt: item.lastSeenAt,
        updatedAt: item.updatedAt
      }))
    };
  }

  async updateSettings(
    viewer: AuthUser,
    input: UpdateSettingsInput,
    sourceIp?: string
  ) {
    await this.ensureSuperAdmin(
      viewer,
      "PATCH /executor-intelligence/settings",
      sourceIp
    );

    const before = await this.ensureSettings();
    const updated = await this.prisma.executorIntelligenceSetting.update({
      where: { id: SETTINGS_ID },
      data: {
        enabled: input.enabled,
        sourceUrl: input.sourceUrl,
        fallbackUrl: input.fallbackUrl,
        cacheTtlSeconds: input.cacheTtlSeconds,
        updatedById: viewer.id
      }
    });

    if (typeof input.enabled === "boolean") {
      await this.prisma.detectionRule.updateMany({
        where: { managedBy: MANAGED_BY, deletedAt: null },
        data: { enabled: input.enabled }
      });
    }

    await this.audit.log({
      actorUserId: viewer.id,
      action: "EXECUTOR_INTELLIGENCE_SETTINGS_UPDATED",
      entityType: "executor_intelligence_settings",
      entityId: updated.id,
      before: this.serializeSettings(before),
      after: this.serializeSettings(updated),
      sourceIp
    });

    return this.getOverview(viewer, sourceIp);
  }

  async sync(viewer: AuthUser, sourceIp?: string) {
    await this.ensureSuperAdmin(
      viewer,
      "POST /executor-intelligence/sync",
      sourceIp
    );
    const settings = await this.ensureSettings();

    if (!settings.lastError && this.isWithinCooldown(settings.lastSyncAt)) {
      return this.getOverview(viewer, sourceIp, "cooldown");
    }

    try {
      const result = await this.performSync(settings, viewer.id);

      await this.audit.log({
        actorUserId: viewer.id,
        action: "EXECUTOR_INTELLIGENCE_SYNCED",
        entityType: "executor_intelligence",
        entityId: SETTINGS_ID,
        after: {
          sourceName: result.sourceName,
          sourceUrl: result.sourceUrl,
          itemCount: result.itemCount,
          windowsItemCount: result.windowsItemCount,
          generatedRuleCount: result.generatedRuleCount
        },
        sourceIp
      });

      return this.getOverview(viewer, sourceIp, "synced");
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Executor intelligence sync failed";
      await this.recordSyncFailure(message, viewer.id);
      throw new BadRequestException("Executor intelligence sync failed");
    }
  }

  private async syncFromScheduler() {
    if (this.syncInFlight) {
      return;
    }

    const settings = await this.ensureSettings();
    if (!settings.enabled || this.cacheIsFresh(settings.lastSuccessAt, settings.cacheTtlSeconds)) {
      return;
    }

    try {
      await this.performSync(settings);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Executor intelligence sync failed";
      await this.recordSyncFailure(message);
    }
  }

  private async performSync(
    settings: Prisma.ExecutorIntelligenceSettingGetPayload<Prisma.ExecutorIntelligenceSettingDefaultArgs>,
    actorUserId?: string
  ) {
    if (this.syncInFlight) {
      throw new Error("Executor intelligence sync already running");
    }
    this.syncInFlight = true;

    try {
      const feed = await this.fetchFeed(settings.sourceUrl, "executors.online").catch(
        () => this.fetchFeed(settings.fallbackUrl, "weao")
      );
      const windowsItems = feed.items
        .filter((item) => !item.hidden && item.title && isWindowsPlatform(item.platform))
        .map((item) => safeItem(item, feed.sourceName, feed.sourceUrl));

      const now = new Date();
      const ruleIds: string[] = [];

      await this.prisma.$transaction(async (tx) => {
        for (const item of windowsItems) {
          const stored = await tx.executorIntelligenceItem.upsert({
            where: {
              sourceName_slug: {
                sourceName: item.sourceName,
                slug: item.slug
              }
            },
            create: {
              ...item,
              extype: item.extype ? sanitizeText(item.extype).slice(0, 80) : null,
              lastSeenAt: now
            },
            update: {
              title: item.title,
              platform: item.platform,
              extype: item.extype ? sanitizeText(item.extype).slice(0, 80) : null,
              detected: item.detected,
              updateStatus: item.updateStatus,
              version: item.version,
              updatedDateText: item.updatedDateText,
              websiteHost: item.websiteHost,
              sourceUrl: item.sourceUrl,
              sourceMetadata: item.sourceMetadata,
              enabled: true,
              lastSeenAt: now
            }
          });

          const generated = await this.upsertGeneratedRules(
            tx,
            stored.id,
            item,
            settings.enabled && stored.enabled
          );
          ruleIds.push(...generated);
          await tx.executorIntelligenceItem.update({
            where: { id: stored.id },
            data: { generatedRuleIds: generated }
          });
        }

        await tx.executorIntelligenceSetting.update({
          where: { id: SETTINGS_ID },
          data: {
            enabled: settings.enabled,
            lastSyncAt: now,
            lastSuccessAt: now,
            lastError: null,
            itemCount: feed.items.length,
            windowsItemCount: windowsItems.length,
            generatedRuleCount: ruleIds.length,
            updatedById: actorUserId
          }
        });
      });

      await this.monitoring.recordMonitoringEvent({
        eventType: "EXECUTOR_INTELLIGENCE_SYNCED",
        message: "Executor intelligence feed sync completed.",
        metadata: {
          sourceName: feed.sourceName,
          windowsItemCount: windowsItems.length,
          generatedRuleCount: ruleIds.length,
          automatic: !actorUserId
        },
        service: "executor-intelligence",
        severity: MonitoringSeverity.INFO
      });

      return {
        sourceName: feed.sourceName,
        sourceUrl: feed.sourceUrl,
        itemCount: feed.items.length,
        windowsItemCount: windowsItems.length,
        generatedRuleCount: ruleIds.length
      };
    } finally {
      this.syncInFlight = false;
    }
  }

  private async recordSyncFailure(message: string, actorUserId?: string) {
    await this.prisma.executorIntelligenceSetting.update({
      where: { id: SETTINGS_ID },
      data: {
        lastSyncAt: new Date(),
        lastError: sanitizeText(message).slice(0, 500),
        updatedById: actorUserId
      }
    });
    await this.monitoring.recordMonitoringEvent({
      eventType: "EXECUTOR_INTELLIGENCE_SYNC_FAILED",
      message: "Executor intelligence feed sync failed; cached rules remain active.",
      metadata: { lastError: message, automatic: !actorUserId },
      service: "executor-intelligence",
      severity: MonitoringSeverity.WARNING
    });
  }

  async ensureSettings() {
    return this.prisma.executorIntelligenceSetting.upsert({
      where: { id: SETTINGS_ID },
      create: {
        id: SETTINGS_ID,
        enabled: env.EXECUTOR_INTEL_ENABLED,
        sourceUrl: env.EXECUTOR_INTEL_SOURCE_URL,
        fallbackUrl: env.EXECUTOR_INTEL_FALLBACK_URL,
        cacheTtlSeconds: env.EXECUTOR_INTEL_CACHE_TTL_SECONDS,
        attribution: ATTRIBUTION
      },
      update: {}
    });
  }

  private async upsertGeneratedRules(
    tx: Prisma.TransactionClient,
    itemId: string,
    item: ReturnType<typeof safeItem>,
    enabled: boolean
  ) {
    const ids: string[] = [];
    const baseConfig = {
      managedBy: MANAGED_BY,
      managedRefId: itemId,
      executorName: item.title,
      executorSlug: item.slug,
      executorType: item.extype,
      detected: item.detected,
      updateStatus: item.updateStatus,
      feedUpdatedAt: item.updatedDateText,
      sourceName: item.sourceName,
      sourceUrl: item.sourceUrl,
      reviewOnly: true,
      warningRequiresMultiSignal: true
    };

    const processRule = await tx.detectionRule.upsert({
      where: {
        managedBy_managedRefId_type: {
          managedBy: MANAGED_BY,
          managedRefId: `${itemId}:process`,
          type: DetectionRuleType.PROCESS_NAME
        }
      },
      create: {
        scope: DetectionRuleScope.GLOBAL,
        name: `Executor intelligence: ${item.title} process`,
        type: DetectionRuleType.PROCESS_NAME,
        category: FindingCategory.CUSTOM_DETECTION,
        severity: Severity.INFO,
        enabled,
        ruleConfig: sanitizeForStorage({
          ...baseConfig,
          matchMode: "exact",
          processNames: processAliases(item.title, item.slug)
        }),
        managedBy: MANAGED_BY,
        managedRefId: `${itemId}:process`
      },
      update: {
        name: `Executor intelligence: ${item.title} process`,
        enabled,
        severity: Severity.INFO,
        ruleConfig: sanitizeForStorage({
          ...baseConfig,
          matchMode: "exact",
          processNames: processAliases(item.title, item.slug)
        }),
        deletedAt: null
      }
    });
    ids.push(processRule.id);

    const patterns = pathPatterns(item.title, item.slug, item.websiteHost);
    if (patterns.length > 0) {
      const pathRule = await tx.detectionRule.upsert({
        where: {
          managedBy_managedRefId_type: {
            managedBy: MANAGED_BY,
            managedRefId: `${itemId}:path`,
            type: DetectionRuleType.PATH_PATTERN
          }
        },
        create: {
          scope: DetectionRuleScope.GLOBAL,
          name: `Executor intelligence: ${item.title} path`,
          type: DetectionRuleType.PATH_PATTERN,
          category: FindingCategory.CUSTOM_DETECTION,
          severity: Severity.INFO,
          enabled,
          ruleConfig: sanitizeForStorage({
            ...baseConfig,
            matchMode: "regex",
            patterns
          }),
          managedBy: MANAGED_BY,
          managedRefId: `${itemId}:path`
        },
        update: {
          name: `Executor intelligence: ${item.title} path`,
          enabled,
          severity: Severity.INFO,
          ruleConfig: sanitizeForStorage({
            ...baseConfig,
            matchMode: "regex",
            patterns
          }),
          deletedAt: null
        }
      });
      ids.push(pathRule.id);
    }

    return ids;
  }

  private async fetchFeed(sourceUrl: string, sourceName: string) {
    const headers =
      sourceName === "weao" ? { "user-agent": "WEAO-3PService" } : undefined;
    const response = await fetch(sourceUrl, { headers });

    if (!response.ok) {
      throw new Error(`Feed ${sourceName} responded with ${response.status}`);
    }

    const payload = (await response.json()) as unknown;
    if (!Array.isArray(payload)) {
      throw new Error(`Feed ${sourceName} returned invalid payload`);
    }

    return {
      sourceName,
      sourceUrl,
      items: payload.filter(isObject).map((item) => item as FeedItem)
    };
  }

  private serializeSettings(
    settings: Prisma.ExecutorIntelligenceSettingGetPayload<Prisma.ExecutorIntelligenceSettingDefaultArgs>
  ) {
    return {
      id: settings.id,
      enabled: settings.enabled,
      sourceUrl: settings.sourceUrl,
      fallbackUrl: settings.fallbackUrl,
      cacheTtlSeconds: settings.cacheTtlSeconds,
      attribution: settings.attribution,
      lastSyncAt: settings.lastSyncAt,
      lastSuccessAt: settings.lastSuccessAt,
      lastError: settings.lastError,
      itemCount: settings.itemCount,
      windowsItemCount: settings.windowsItemCount,
      generatedRuleCount: settings.generatedRuleCount,
      updatedById: settings.updatedById,
      createdAt: settings.createdAt,
      updatedAt: settings.updatedAt
    };
  }

  private cacheIsFresh(lastSuccessAt: Date | null, ttlSeconds: number) {
    if (!lastSuccessAt) {
      return false;
    }

    return Date.now() - lastSuccessAt.getTime() < ttlSeconds * 1000;
  }

  private isWithinCooldown(lastSyncAt: Date | null) {
    if (!lastSyncAt) {
      return false;
    }

    return (
      Date.now() - lastSyncAt.getTime() <
      env.EXECUTOR_INTEL_SYNC_COOLDOWN_SECONDS * 1000
    );
  }

  private async ensureSuperAdmin(
    viewer: AuthUser,
    route: string,
    sourceIp?: string
  ) {
    if (isSuperAdmin(viewer)) {
      return;
    }

    await this.monitoring.recordSecurityEvent({
      actorUserId: viewer.id,
      eventType: "PERMISSION_DENIED",
      message: "Non-Super Admin attempted to access executor intelligence.",
      metadata: { route, userId: viewer.id },
      severity: MonitoringSeverity.WARNING,
      sourceIp
    });

    throw new ForbiddenException("Super Admin access required");
  }
}
