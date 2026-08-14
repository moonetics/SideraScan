import {
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException
} from "@nestjs/common";
import {
  AccountRole,
  AccountStatus,
  DetectionRuleScope,
  DetectionRuleType,
  DetectionSampleStatus,
  FindingCategory,
  Prisma,
  ScannerKeyStatus,
  Severity
} from "@prisma/client";
import { createHash } from "node:crypto";
import { AuditService } from "../audit/audit.service";
import { isSuperAdmin } from "../auth/authz";
import type { AuthUser } from "../auth/auth.types";
import { sanitizeForStorage, sanitizeText } from "../common/data-sanitizer";
import { env } from "../config/env";
import { PrismaService } from "../prisma/prisma.service";
import { hashScannerKey } from "../scanner-keys/scanner-key-crypto";

type CreateRuleInput = {
  accountId?: string;
  scope: DetectionRuleScope;
  name: string;
  type: DetectionRuleType;
  category: FindingCategory;
  severity: Severity;
  enabled: boolean;
  ruleConfig: unknown;
};

type UpdateRuleInput = {
  name?: string;
  category?: FindingCategory;
  severity?: Severity;
  enabled?: boolean;
  ruleConfig?: unknown;
};

type UploadSampleInput = {
  accountId?: string;
  fileName: string;
  contentBase64: string;
};

type ScannerConfigInput = {
  scannerKey: string;
  scannerVersion: string;
};

type AdvancedForensicsReviewMode =
  | "ai_assisted_full"
  | "review_relevant_only";

const ruleInclude = {
  account: { select: { id: true, name: true } },
  createdBy: { select: { id: true, displayName: true } }
} satisfies Prisma.DetectionRuleInclude;

const sampleInclude = {
  account: { select: { id: true, name: true } },
  uploadedBy: { select: { id: true, displayName: true } },
  _count: { select: { strings: true } }
} satisfies Prisma.DetectionSampleInclude;

type DetectionRuleWithRelations = Prisma.DetectionRuleGetPayload<{
  include: typeof ruleInclude;
}>;
type DetectionSampleWithRelations = Prisma.DetectionSampleGetPayload<{
  include: typeof sampleInclude;
}>;

function sha256(value: Buffer | string) {
  return createHash("sha256").update(value).digest("hex");
}

function toJson(value: unknown): Prisma.InputJsonValue {
  return sanitizeForStorage(value);
}

export function resolveAdvancedForensicsReviewMode(input: {
  n8nWebhookEnabled: boolean;
  scanCompletedWebhookUrl?: string | null;
}): AdvancedForensicsReviewMode {
  return input.n8nWebhookEnabled && Boolean(input.scanCompletedWebhookUrl)
    ? "ai_assisted_full"
    : "review_relevant_only";
}

function normalizeBase64(value: string) {
  const cleaned = value.includes(",") ? value.split(",").pop() ?? "" : value;
  return cleaned.trim();
}

function printableStrings(buffer: Buffer) {
  const values = new Map<string, { valueHash: string; preview: string; length: number }>();
  let current = "";

  function flush() {
    if (current.length >= 4) {
      const valueHash = sha256(current);
      values.set(valueHash, {
        valueHash,
        preview: sanitizeText(current.slice(0, 160)),
        length: current.length
      });
    }
    current = "";
  }

  for (const byte of buffer) {
    if (byte >= 32 && byte <= 126) {
      current += String.fromCharCode(byte);
    } else {
      flush();
    }
  }
  flush();

  return Array.from(values.values())
    .sort((left, right) => right.length - left.length)
    .slice(0, 500);
}

function serializeRule(rule: DetectionRuleWithRelations) {
  return {
    id: rule.id,
    accountId: rule.accountId,
    accountName: rule.account?.name ?? null,
    scope: rule.scope,
    name: rule.name,
    type: rule.type,
    category: rule.category,
    severity: rule.severity,
    enabled: rule.enabled,
    managedBy: rule.managedBy,
    managedRefId: rule.managedRefId,
    ruleConfig: sanitizeForStorage(rule.ruleConfig),
    hitCount: rule.hitCount,
    createdBy: rule.createdBy,
    createdAt: rule.createdAt,
    updatedAt: rule.updatedAt
  };
}

function serializeSample(sample: DetectionSampleWithRelations) {
  return {
    id: sample.id,
    accountId: sample.accountId,
    accountName: sample.account?.name ?? null,
    uploadedBy: sample.uploadedBy,
    fileName: sample.fileName,
    fileHash: sample.fileHash,
    sizeBytes: sample.sizeBytes,
    status: sample.status,
    stringCount: sample._count.strings,
    createdAt: sample.createdAt,
    deletedAt: sample.deletedAt
  };
}

@Injectable()
export class DetectionsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService
  ) {}

  async listRules(viewer: AuthUser) {
    const rules = await this.prisma.detectionRule.findMany({
      where: this.visibleRuleWhere(viewer),
      include: ruleInclude,
      orderBy: { createdAt: "desc" }
    });

    return rules.map(serializeRule);
  }

  async createRule(
    viewer: AuthUser,
    input: CreateRuleInput,
    sourceIp?: string
  ) {
    await this.ensureCanManageScope(viewer, input.scope, input.accountId);

    const rule = await this.prisma.detectionRule.create({
      data: {
        accountId:
          input.scope === DetectionRuleScope.ACCOUNT ? input.accountId : null,
        scope: input.scope,
        name: sanitizeText(input.name.trim()),
        type: input.type,
        category: input.category,
        severity: input.severity,
        enabled: input.enabled,
        ruleConfig: toJson(input.ruleConfig),
        createdById: viewer.id
      },
      include: ruleInclude
    });

    await this.audit.log({
      accountId: rule.accountId,
      actorUserId: viewer.id,
      action: "DETECTION_RULE_CREATED",
      entityType: "detection_rule",
      entityId: rule.id,
      after: {
        scope: rule.scope,
        accountId: rule.accountId,
        type: rule.type,
        severity: rule.severity,
        enabled: rule.enabled
      },
      sourceIp
    });

    return serializeRule(rule);
  }

  async updateRule(
    viewer: AuthUser,
    ruleId: string,
    input: UpdateRuleInput,
    sourceIp?: string
  ) {
    const current = await this.findAccessibleRule(viewer, ruleId);
    if (current.managedBy === "EXECUTOR_INTELLIGENCE") {
      throw new ForbiddenException(
        "Executor intelligence rules are managed from Executor Intelligence"
      );
    }
    await this.ensureCanManageScope(viewer, current.scope, current.accountId ?? undefined);

    const updated = await this.prisma.detectionRule.update({
      where: { id: ruleId },
      data: {
        name: input.name ? sanitizeText(input.name.trim()) : undefined,
        category: input.category,
        severity: input.severity,
        enabled: input.enabled,
        ruleConfig:
          input.ruleConfig === undefined ? undefined : toJson(input.ruleConfig)
      },
      include: ruleInclude
    });

    await this.audit.log({
      accountId: updated.accountId,
      actorUserId: viewer.id,
      action: "DETECTION_RULE_UPDATED",
      entityType: "detection_rule",
      entityId: updated.id,
      before: {
        name: current.name,
        severity: current.severity,
        enabled: current.enabled,
        ruleConfig: current.ruleConfig
      },
      after: {
        name: updated.name,
        severity: updated.severity,
        enabled: updated.enabled,
        ruleConfig: updated.ruleConfig
      },
      sourceIp
    });

    return serializeRule(updated);
  }

  async disableRule(viewer: AuthUser, ruleId: string, sourceIp?: string) {
    return this.updateRule(viewer, ruleId, { enabled: false }, sourceIp);
  }

  async uploadSample(
    viewer: AuthUser,
    input: UploadSampleInput,
    sourceIp?: string
  ) {
    if (input.accountId) {
      await this.ensureCanManageScope(
        viewer,
        DetectionRuleScope.ACCOUNT,
        input.accountId
      );
    } else if (!isSuperAdmin(viewer)) {
      throw new ForbiddenException("Account Owner access required");
    }

    const bytes = Buffer.from(normalizeBase64(input.contentBase64), "base64");

    if (bytes.length === 0 || bytes.length > 2_000_000) {
      throw new ForbiddenException("Invalid sample size");
    }

    const extractedStrings = printableStrings(bytes);
    const fileHash = sha256(bytes);
    const sample = await this.prisma.detectionSample.create({
      data: {
        accountId: input.accountId ?? null,
        uploadedById: viewer.id,
        fileName: sanitizeText(input.fileName.trim()),
        fileHash,
        storageRef: null,
        sizeBytes: bytes.length,
        status:
          extractedStrings.length > 0
            ? DetectionSampleStatus.PURGED
            : DetectionSampleStatus.FAILED,
        deletedAt: new Date(),
        strings:
          extractedStrings.length > 0
            ? {
                createMany: {
                  data: extractedStrings.map((item) => ({
                    valueHash: item.valueHash,
                    preview: item.preview,
                    length: item.length
                  }))
                }
              }
            : undefined
      },
      include: sampleInclude
    });

    await this.audit.log({
      accountId: sample.accountId,
      actorUserId: viewer.id,
      action: "DETECTION_SAMPLE_UPLOADED",
      entityType: "detection_sample",
      entityId: sample.id,
      after: {
        fileName: sample.fileName,
        fileHash: sample.fileHash,
        sizeBytes: sample.sizeBytes,
        status: sample.status,
        extractedStrings: extractedStrings.length,
        rawSampleStored: false
      },
      sourceIp
    });

    return serializeSample(sample);
  }

  async getSampleStrings(viewer: AuthUser, sampleId: string) {
    const sample = await this.prisma.detectionSample.findFirst({
      where: {
        id: sampleId,
        ...this.visibleSampleWhere(viewer)
      },
      include: {
        strings: { orderBy: { length: "desc" }, take: 500 },
        ...sampleInclude
      }
    });

    if (!sample) {
      throw new NotFoundException("Detection sample not found");
    }

    return {
      sample: serializeSample(sample),
      strings: sample.strings.map((item) => ({
        id: item.id,
        sampleId: item.sampleId,
        valueHash: item.valueHash,
        preview: item.preview,
        length: item.length,
        selectedForRule: item.selectedForRule,
        createdAt: item.createdAt
      }))
    };
  }

  async getScannerConfig(input: ScannerConfigInput) {
    const scannerKey = await this.prisma.scannerKey.findFirst({
      where: {
        keyHash: hashScannerKey(input.scannerKey),
        status: ScannerKeyStatus.ACTIVE
      },
      include: { account: true }
    });

    if (!scannerKey || scannerKey.expiresAt && scannerKey.expiresAt <= new Date()) {
      throw new UnauthorizedException("Invalid scanner key");
    }

    if (
      scannerKey.account.status !== AccountStatus.ACTIVE ||
      scannerKey.account.deletedAt
    ) {
      throw new UnauthorizedException("Account disabled");
    }

    if (
      Array.isArray(scannerKey.allowedScannerVersions) &&
      scannerKey.allowedScannerVersions.length > 0 &&
      !scannerKey.allowedScannerVersions.includes(input.scannerVersion)
    ) {
      throw new UnauthorizedException("Scanner version not allowed");
    }

    const executorIntelSetting =
      await this.prisma.executorIntelligenceSetting.findUnique({
        where: { id: "global" },
        select: { enabled: true }
      });
    const executorIntelEnabled =
      env.EXECUTOR_INTEL_ENABLED && (executorIntelSetting?.enabled ?? true);

    const rules = await this.prisma.detectionRule.findMany({
      where: {
        deletedAt: null,
        enabled: true,
        AND: [
          executorIntelEnabled
            ? {}
            : {
                OR: [
                  { managedBy: null },
                  { managedBy: { not: "EXECUTOR_INTELLIGENCE" } }
                ]
              }
        ],
        OR: [
          { scope: DetectionRuleScope.GLOBAL, accountId: null },
          { scope: DetectionRuleScope.ACCOUNT, accountId: scannerKey.accountId }
        ]
      },
      include: ruleInclude,
      orderBy: { updatedAt: "desc" }
    });

    const reviewMode = resolveAdvancedForensicsReviewMode({
      n8nWebhookEnabled: env.N8N_WEBHOOK_ENABLED,
      scanCompletedWebhookUrl: env.N8N_SCAN_COMPLETED_WEBHOOK_URL
    });

    return {
      status: "ok",
      accountId: scannerKey.accountId,
      accountName: scannerKey.account.name,
      scannerVersion: input.scannerVersion,
      advancedForensics: {
        enabled: true,
        reviewMode,
        modules: {
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
          forensicTimeline: true
        },
        maxRowsPerModule: 250,
        maxFileHashMB: 100,
        maxPayloadBytes: 25165824,
        maxTimelineRows: 350,
        browserDownloadHistory: false,
        discordTelegramMetadata: false
      },
      rules: rules.map((rule) => ({
        id: rule.id,
        scope: rule.scope,
        accountId: rule.accountId,
        name: rule.name,
        type: rule.type,
        category: rule.category,
        severity: rule.severity,
        managedBy: rule.managedBy,
        managedRefId: rule.managedRefId,
        ruleConfig: sanitizeForStorage(rule.ruleConfig),
        updatedAt: rule.updatedAt
      }))
    };
  }

  private visibleRuleWhere(viewer: AuthUser): Prisma.DetectionRuleWhereInput {
    if (isSuperAdmin(viewer)) {
      return { deletedAt: null };
    }

    return {
      deletedAt: null,
      OR: [
        { scope: DetectionRuleScope.GLOBAL },
        {
          account: {
            deletedAt: null,
            status: { not: AccountStatus.DELETED },
            memberships: { some: { userId: viewer.id } }
          }
        }
      ]
    };
  }

  private visibleSampleWhere(viewer: AuthUser): Prisma.DetectionSampleWhereInput {
    if (isSuperAdmin(viewer)) {
      return {};
    }

    return {
      OR: [
        { accountId: null },
        {
          account: {
            deletedAt: null,
            status: { not: AccountStatus.DELETED },
            memberships: { some: { userId: viewer.id } }
          }
        }
      ]
    };
  }

  private async findAccessibleRule(viewer: AuthUser, ruleId: string) {
    const rule = await this.prisma.detectionRule.findFirst({
      where: {
        id: ruleId,
        ...this.visibleRuleWhere(viewer)
      },
      include: ruleInclude
    });

    if (!rule) {
      throw new NotFoundException("Detection rule not found");
    }

    return rule;
  }

  private async ensureCanManageScope(
    viewer: AuthUser,
    scope: DetectionRuleScope,
    accountId?: string
  ) {
    if (scope === DetectionRuleScope.GLOBAL) {
      if (!isSuperAdmin(viewer)) {
        throw new ForbiddenException("Super Admin access required");
      }

      return;
    }

    if (!accountId) {
      throw new ForbiddenException("Account scoped rules require accountId");
    }

    if (isSuperAdmin(viewer)) {
      return;
    }

    const membership = await this.prisma.userAccount.findUnique({
      where: {
        userId_accountId: {
          userId: viewer.id,
          accountId
        }
      },
      select: { role: true }
    });

    if (!membership) {
      throw new NotFoundException("Account not found");
    }

    if (membership.role !== AccountRole.ACCOUNT_OWNER) {
      throw new ForbiddenException("Account Owner access required");
    }
  }
}
