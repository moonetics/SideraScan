import { ForbiddenException, Injectable, NotFoundException } from "@nestjs/common";
import {
  AccountRole,
  AccountStatus,
  GlobalRole,
  Prisma,
  ScannerKeyStatus
} from "@prisma/client";
import { AuditService } from "../audit/audit.service";
import { isSuperAdmin } from "../auth/authz";
import type { AuthUser } from "../auth/auth.types";
import { PrismaService } from "../prisma/prisma.service";
import {
  generateRawScannerKey,
  getScannerKeyPrefix,
  hashScannerKey
} from "./scanner-key-crypto";

const scannerKeyInclude = {
  account: {
    select: {
      id: true,
      name: true
    }
  }
} satisfies Prisma.ScannerKeyInclude;

type ScannerKeyWithAccount = Prisma.ScannerKeyGetPayload<{
  include: typeof scannerKeyInclude;
}>;

export type CreateScannerKeyInput = {
  name: string;
  expiresAt?: Date | null;
  rateLimitPerHour?: number;
  allowedScannerVersions?: string[];
};

function serializeScannerKey(scannerKey: ScannerKeyWithAccount) {
  return {
    id: scannerKey.id,
    accountId: scannerKey.accountId,
    accountName: scannerKey.account.name,
    name: scannerKey.name,
    keyPrefix: scannerKey.keyPrefix,
    status: scannerKey.status,
    createdAt: scannerKey.createdAt,
    updatedAt: scannerKey.updatedAt,
    lastUsedAt: scannerKey.lastUsedAt,
    usageCount: scannerKey.usageCount,
    expiresAt: scannerKey.expiresAt,
    rateLimitPerHour: scannerKey.rateLimitPerHour,
    allowedScannerVersions: scannerKey.allowedScannerVersions ?? []
  };
}

function allowedVersionsJson(
  versions: string[] | undefined
): Prisma.InputJsonValue | undefined {
  if (versions === undefined) {
    return undefined;
  }

  return versions;
}

@Injectable()
export class ScannerKeysService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService
  ) {}

  async listVisibleKeys(viewer: AuthUser) {
    const accountWhere: Prisma.AccountWhereInput = {
      deletedAt: null,
      status: { not: AccountStatus.DELETED }
    };

    if (!isSuperAdmin(viewer)) {
      accountWhere.memberships = { some: { userId: viewer.id } };
    }

    const where: Prisma.ScannerKeyWhereInput = {
      account: accountWhere
    };

    const scannerKeys = await this.prisma.scannerKey.findMany({
      where,
      include: scannerKeyInclude,
      orderBy: { createdAt: "desc" }
    });

    return scannerKeys.map(serializeScannerKey);
  }

  async listAccountKeys(viewer: AuthUser, accountId: string) {
    await this.ensureAccountAccess(viewer, accountId);

    const scannerKeys = await this.prisma.scannerKey.findMany({
      where: { accountId },
      include: scannerKeyInclude,
      orderBy: { createdAt: "desc" }
    });

    return scannerKeys.map(serializeScannerKey);
  }

  async createKey(
    viewer: AuthUser,
    accountId: string,
    input: CreateScannerKeyInput,
    sourceIp?: string
  ) {
    await this.ensureCanManageKeys(viewer, accountId);

    const rawKey = generateRawScannerKey();
    const keyPrefix = getScannerKeyPrefix(rawKey);
    const keyHash = hashScannerKey(rawKey);
    const scannerKey = await this.prisma.scannerKey.create({
      data: {
        accountId,
        name: input.name.trim(),
        keyPrefix,
        keyHash,
        createdById: viewer.id,
        expiresAt: input.expiresAt,
        rateLimitPerHour: input.rateLimitPerHour ?? 60,
        allowedScannerVersions: allowedVersionsJson(
          input.allowedScannerVersions
        )
      },
      include: scannerKeyInclude
    });

    await this.audit.log({
      accountId,
      actorUserId: viewer.id,
      action: "SCANNER_KEY_CREATED",
      entityType: "scanner_key",
      entityId: scannerKey.id,
      after: {
        name: scannerKey.name,
        keyPrefix: scannerKey.keyPrefix,
        status: scannerKey.status,
        rateLimitPerHour: scannerKey.rateLimitPerHour,
        allowedScannerVersions: scannerKey.allowedScannerVersions
      },
      sourceIp
    });

    return {
      scannerKey: serializeScannerKey(scannerKey),
      rawKey
    };
  }

  async rotateKey(viewer: AuthUser, scannerKeyId: string, sourceIp?: string) {
    const current = await this.findAccessibleKey(viewer, scannerKeyId);
    await this.ensureCanManageKeys(viewer, current.accountId);

    const rawKey = generateRawScannerKey();
    const keyPrefix = getScannerKeyPrefix(rawKey);
    const keyHash = hashScannerKey(rawKey);
    const updated = await this.prisma.scannerKey.update({
      where: { id: scannerKeyId },
      data: {
        keyPrefix,
        keyHash,
        status: ScannerKeyStatus.ACTIVE,
        revokedAt: null,
        revokedById: null
      },
      include: scannerKeyInclude
    });

    await this.audit.log({
      accountId: updated.accountId,
      actorUserId: viewer.id,
      action: "SCANNER_KEY_ROTATED",
      entityType: "scanner_key",
      entityId: updated.id,
      before: {
        keyPrefix: current.keyPrefix,
        status: current.status
      },
      after: {
        keyPrefix: updated.keyPrefix,
        status: updated.status
      },
      sourceIp
    });

    return {
      scannerKey: serializeScannerKey(updated),
      rawKey
    };
  }

  async revokeKey(viewer: AuthUser, scannerKeyId: string, sourceIp?: string) {
    const current = await this.findAccessibleKey(viewer, scannerKeyId);
    await this.ensureCanManageKeys(viewer, current.accountId);

    const updated = await this.prisma.scannerKey.update({
      where: { id: scannerKeyId },
      data: {
        status: ScannerKeyStatus.REVOKED,
        revokedAt: new Date(),
        revokedById: viewer.id
      },
      include: scannerKeyInclude
    });

    await this.audit.log({
      accountId: updated.accountId,
      actorUserId: viewer.id,
      action: "SCANNER_KEY_REVOKED",
      entityType: "scanner_key",
      entityId: updated.id,
      before: {
        keyPrefix: current.keyPrefix,
        status: current.status
      },
      after: {
        keyPrefix: updated.keyPrefix,
        status: updated.status
      },
      sourceIp
    });

    return serializeScannerKey(updated);
  }

  private async ensureAccountAccess(viewer: AuthUser, accountId: string) {
    const account = await this.prisma.account.findFirst({
      where: {
        id: accountId,
        deletedAt: null,
        status: { not: AccountStatus.DELETED },
        ...(viewer.globalRole === GlobalRole.SUPER_ADMIN
          ? {}
          : { memberships: { some: { userId: viewer.id } } })
      },
      select: { id: true }
    });

    if (!account) {
      throw new NotFoundException("Account not found");
    }
  }

  private async ensureCanManageKeys(viewer: AuthUser, accountId: string) {
    if (viewer.globalRole === GlobalRole.SUPER_ADMIN) {
      await this.ensureAccountAccess(viewer, accountId);
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

  private async findAccessibleKey(viewer: AuthUser, scannerKeyId: string) {
    const scannerKey = await this.prisma.scannerKey.findFirst({
      where: {
        id: scannerKeyId,
        account: {
          deletedAt: null,
          status: { not: AccountStatus.DELETED },
          ...(viewer.globalRole === GlobalRole.SUPER_ADMIN
            ? {}
            : { memberships: { some: { userId: viewer.id } } })
        }
      },
      include: scannerKeyInclude
    });

    if (!scannerKey) {
      throw new NotFoundException("Scanner key not found");
    }

    return scannerKey;
  }
}
