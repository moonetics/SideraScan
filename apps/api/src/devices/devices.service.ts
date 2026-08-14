import {
  ForbiddenException,
  Injectable,
  NotFoundException
} from "@nestjs/common";
import {
  AccountRole,
  AccountStatus,
  DeviceMarkScope,
  DeviceMarkStatus,
  Prisma,
  Severity
} from "@prisma/client";
import { AuditService } from "../audit/audit.service";
import { isSuperAdmin } from "../auth/authz";
import type { AuthUser } from "../auth/auth.types";
import { PrismaService } from "../prisma/prisma.service";

type CreateMarkInput = {
  status: DeviceMarkStatus;
  scope: DeviceMarkScope;
  accountId?: string;
  reason: string;
  expiresAt?: Date;
  evidenceScanSessionId?: string;
  evidenceFindingId?: string;
  note?: string;
};

type UpdateMarkInput = {
  status?: DeviceMarkStatus;
  reason?: string;
  expiresAt?: Date | null;
};

const deviceInclude = {
  accountLinks: {
    include: {
      account: {
        select: {
          id: true,
          name: true,
          slug: true,
          status: true,
          memberships: { select: { userId: true } }
        }
      }
    },
    orderBy: { lastSeenAt: "desc" }
  },
  marks: {
    include: {
      account: { select: { id: true, name: true } },
      markedBy: { select: { id: true, displayName: true } },
      revokedBy: { select: { id: true, displayName: true } },
      evidence: true
    },
    orderBy: { markedAt: "desc" }
  },
  scanSessions: {
    include: {
      account: { select: { id: true, name: true } },
      scannerKey: { select: { keyPrefix: true, name: true } },
      _count: { select: { findings: true } }
    },
    orderBy: { createdAt: "desc" },
    take: 20
  }
} satisfies Prisma.DeviceInclude;

const markInclude = {
  account: { select: { id: true, name: true } },
  markedBy: { select: { id: true, displayName: true } },
  revokedBy: { select: { id: true, displayName: true } },
  evidence: true,
  device: { select: { id: true, fingerprintPrefix: true } }
} satisfies Prisma.DeviceMarkInclude;

type DeviceWithDetails = Prisma.DeviceGetPayload<{ include: typeof deviceInclude }>;
type DeviceMarkWithDetails = Prisma.DeviceMarkGetPayload<{
  include: typeof markInclude;
}>;

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

function isActiveMark(mark: { revokedAt: Date | null; expiresAt: Date | null }) {
  return !mark.revokedAt && (!mark.expiresAt || mark.expiresAt > new Date());
}

function safeMark(mark: DeviceMarkWithDetails | DeviceWithDetails["marks"][number]) {
  return {
    id: mark.id,
    deviceId: mark.deviceId,
    scope: mark.scope,
    accountId: mark.accountId,
    accountName: mark.account?.name ?? null,
    status: mark.status,
    severity: mark.severity,
    reason: mark.reason,
    markedAt: mark.markedAt,
    markedBy: mark.markedBy,
    expiresAt: mark.expiresAt,
    revokedAt: mark.revokedAt,
    revokedBy: mark.revokedBy,
    evidence: mark.evidence.map((evidence) => ({
      id: evidence.id,
      scanSessionId: evidence.scanSessionId,
      findingId: evidence.findingId,
      note: evidence.note,
      createdAt: evidence.createdAt
    }))
  };
}

function safeScan(scan: DeviceWithDetails["scanSessions"][number]) {
  return {
    id: scan.id,
    accountId: scan.accountId,
    accountName: scan.account.name,
    playerLabel: scan.playerLabel,
    status: scan.status,
    scannerVersion: scan.scannerVersion,
    scannerKeyName: scan.scannerKey.name,
    scannerKeyPrefix: scan.scannerKey.keyPrefix,
    riskScore: scan.riskScore,
    maxSeverity: scan.maxSeverity,
    findingCount: scan._count.findings,
    startedAt: scan.startedAt,
    finishedAt: scan.finishedAt,
    createdAt: scan.createdAt
  };
}

@Injectable()
export class DevicesService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService
  ) {}

  async listDevices(viewer: AuthUser) {
    const devices = await this.prisma.device.findMany({
      where: this.visibleDeviceWhere(viewer),
      include: deviceInclude,
      orderBy: { lastSeenAt: "desc" },
      take: 200
    });

    return devices.map((device) => this.serializeDeviceListItem(device, viewer));
  }

  async getDevice(viewer: AuthUser, deviceId: string) {
    const device = await this.findAccessibleDevice(viewer, deviceId);

    return this.serializeDeviceDetail(device, viewer);
  }

  async getDeviceScans(viewer: AuthUser, deviceId: string) {
    const device = await this.findAccessibleDevice(viewer, deviceId);

    return device.scanSessions
      .filter((scan) => this.canViewAccount(viewer, scan.accountId, device))
      .map(safeScan);
  }

  async createMark(
    viewer: AuthUser,
    deviceId: string,
    input: CreateMarkInput,
    sourceIp?: string
  ) {
    await this.ensureCanMark(viewer, deviceId, input.scope, input.accountId);

    const mark = await this.prisma.deviceMark.create({
      data: {
        deviceId,
        scope: input.scope,
        accountId:
          input.scope === DeviceMarkScope.ACCOUNT ? input.accountId : null,
        status: input.status,
        severity: markSeverity(input.status),
        reason: input.reason.trim(),
        expiresAt: input.expiresAt,
        markedById: viewer.id,
        evidence:
          input.evidenceScanSessionId || input.evidenceFindingId || input.note
            ? {
                create: {
                  scanSessionId: input.evidenceScanSessionId,
                  findingId: input.evidenceFindingId,
                  note: input.note?.trim() || null
                }
              }
            : undefined
      },
      include: markInclude
    });

    await this.audit.log({
      accountId: mark.accountId,
      actorUserId: viewer.id,
      action: "DEVICE_MARK_CREATED",
      entityType: "device_mark",
      entityId: mark.id,
      after: {
        deviceId,
        fingerprintPrefix: mark.device.fingerprintPrefix,
        scope: mark.scope,
        accountId: mark.accountId,
        status: mark.status,
        reason: mark.reason,
        expiresAt: mark.expiresAt
      },
      sourceIp
    });

    return safeMark(mark);
  }

  async updateMark(
    viewer: AuthUser,
    markId: string,
    input: UpdateMarkInput,
    sourceIp?: string
  ) {
    const current = await this.findAccessibleMark(viewer, markId);
    await this.ensureCanManageMark(viewer, current);

    const updated = await this.prisma.deviceMark.update({
      where: { id: markId },
      data: {
        status: input.status,
        severity: input.status ? markSeverity(input.status) : undefined,
        reason: input.reason?.trim(),
        expiresAt: input.expiresAt
      },
      include: markInclude
    });

    await this.audit.log({
      accountId: updated.accountId,
      actorUserId: viewer.id,
      action: "DEVICE_MARK_UPDATED",
      entityType: "device_mark",
      entityId: updated.id,
      before: {
        status: current.status,
        reason: current.reason,
        expiresAt: current.expiresAt
      },
      after: {
        status: updated.status,
        reason: updated.reason,
        expiresAt: updated.expiresAt
      },
      sourceIp
    });

    return safeMark(updated);
  }

  async revokeMark(
    viewer: AuthUser,
    markId: string,
    reason: string,
    sourceIp?: string
  ) {
    const current = await this.findAccessibleMark(viewer, markId);
    await this.ensureCanManageMark(viewer, current);

    const updated = await this.prisma.deviceMark.update({
      where: { id: markId },
      data: {
        revokedAt: new Date(),
        revokedById: viewer.id
      },
      include: markInclude
    });

    await this.audit.log({
      accountId: updated.accountId,
      actorUserId: viewer.id,
      action: "DEVICE_MARK_REVOKED",
      entityType: "device_mark",
      entityId: updated.id,
      before: {
        status: current.status,
        revokedAt: current.revokedAt
      },
      after: {
        status: updated.status,
        revokedAt: updated.revokedAt,
        reason: reason.trim()
      },
      sourceIp
    });

    return safeMark(updated);
  }

  private serializeDeviceListItem(device: DeviceWithDetails, viewer: AuthUser) {
    const currentMark = this.currentVisibleMark(device, viewer);

    return {
      id: device.id,
      fingerprintPrefix: device.fingerprintPrefix,
      fingerprintVersion: device.fingerprintVersion,
      fingerprintConfidence: device.fingerprintConfidence,
      firstSeenAt: device.firstSeenAt,
      lastSeenAt: device.lastSeenAt,
      scanCount: device.scanCount,
      currentMark: currentMark ? safeMark(currentMark) : null,
      accounts: device.accountLinks
        .filter((link) => this.canViewAccount(viewer, link.accountId, device))
        .map((link) => ({
          id: link.account.id,
          name: link.account.name,
          slug: link.account.slug,
          status: link.account.status,
          scanCount: link.scanCount,
          firstSeenAt: link.firstSeenAt,
          lastSeenAt: link.lastSeenAt
        }))
    };
  }

  private serializeDeviceDetail(device: DeviceWithDetails, viewer: AuthUser) {
    const listItem = this.serializeDeviceListItem(device, viewer);

    return {
      ...listItem,
      marks: device.marks
        .filter((mark) => this.canViewMark(viewer, mark, device))
        .map(safeMark),
      scanHistory: device.scanSessions
        .filter((scan) => this.canViewAccount(viewer, scan.accountId, device))
        .map(safeScan)
    };
  }

  private currentVisibleMark(device: DeviceWithDetails, viewer: AuthUser) {
    return device.marks
      .filter((mark) => isActiveMark(mark))
      .filter((mark) => this.canViewMark(viewer, mark, device))
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

  private visibleDeviceWhere(viewer: AuthUser): Prisma.DeviceWhereInput {
    if (isSuperAdmin(viewer)) {
      return {};
    }

    return {
      accountLinks: {
        some: {
          account: {
            deletedAt: null,
            status: { not: AccountStatus.DELETED },
            memberships: { some: { userId: viewer.id } }
          }
        }
      }
    };
  }

  private async findAccessibleDevice(viewer: AuthUser, deviceId: string) {
    const device = await this.prisma.device.findFirst({
      where: {
        id: deviceId,
        ...this.visibleDeviceWhere(viewer)
      },
      include: deviceInclude
    });

    if (!device) {
      throw new NotFoundException("Device not found");
    }

    return device;
  }

  private async findAccessibleMark(viewer: AuthUser, markId: string) {
    const mark = await this.prisma.deviceMark.findFirst({
      where: {
        id: markId,
        device: this.visibleDeviceWhere(viewer)
      },
      include: markInclude
    });

    if (!mark) {
      throw new NotFoundException("Device mark not found");
    }

    return mark;
  }

  private canViewAccount(
    viewer: AuthUser,
    accountId: string,
    device: DeviceWithDetails
  ) {
    const link = device.accountLinks.find((item) => item.accountId === accountId);

    return (
      isSuperAdmin(viewer) ||
      Boolean(link?.account.memberships.some((item) => item.userId === viewer.id))
    );
  }

  private canViewMark(
    viewer: AuthUser,
    mark: DeviceWithDetails["marks"][number],
    device: DeviceWithDetails
  ) {
    return (
      isSuperAdmin(viewer) ||
      mark.scope === DeviceMarkScope.GLOBAL ||
      (mark.accountId !== null && this.canViewAccount(viewer, mark.accountId, device))
    );
  }

  private async ensureCanMark(
    viewer: AuthUser,
    deviceId: string,
    scope: DeviceMarkScope,
    accountId?: string
  ) {
    await this.findAccessibleDevice(viewer, deviceId);

    if (scope === DeviceMarkScope.GLOBAL) {
      if (!isSuperAdmin(viewer)) {
        throw new ForbiddenException("Super Admin access required");
      }

      return;
    }

    if (!accountId) {
      throw new ForbiddenException("Account scoped marks require accountId");
    }

    await this.ensureCanManageAccountMark(viewer, accountId);
  }

  private async ensureCanManageMark(
    viewer: AuthUser,
    mark: DeviceMarkWithDetails
  ) {
    if (mark.scope === DeviceMarkScope.GLOBAL) {
      if (!isSuperAdmin(viewer)) {
        throw new ForbiddenException("Super Admin access required");
      }

      return;
    }

    if (!mark.accountId) {
      throw new ForbiddenException("Invalid account scoped mark");
    }

    await this.ensureCanManageAccountMark(viewer, mark.accountId);
  }

  private async ensureCanManageAccountMark(viewer: AuthUser, accountId: string) {
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
