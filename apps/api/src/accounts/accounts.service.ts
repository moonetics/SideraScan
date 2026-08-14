import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException
} from "@nestjs/common";
import {
  AccountRole,
  AccountStatus,
  GlobalRole,
  Prisma
} from "@prisma/client";
import { AuditService } from "../audit/audit.service";
import { isSuperAdmin, requireSuperAdmin } from "../auth/authz";
import type { AuthUser } from "../auth/auth.types";
import { PrismaService } from "../prisma/prisma.service";

const accountListInclude = {
  _count: { select: { memberships: true } },
  memberships: { select: { userId: true, role: true } }
} satisfies Prisma.AccountInclude;

const accountDetailInclude = {
  memberships: {
    orderBy: { createdAt: "asc" },
    select: {
      id: true,
      role: true,
      createdAt: true,
      updatedAt: true,
      user: {
        select: {
          id: true,
          email: true,
          username: true,
          displayName: true,
          globalRole: true,
          status: true
        }
      }
    }
  },
  auditLogs: {
    orderBy: { createdAt: "desc" },
    take: 20
  }
} satisfies Prisma.AccountInclude;

type AccountListItem = Prisma.AccountGetPayload<{
  include: typeof accountListInclude;
}>;
type AccountDetail = Prisma.AccountGetPayload<{
  include: typeof accountDetailInclude;
}>;

export type CreateAccountInput = {
  name: string;
  slug?: string;
};

export type UpdateAccountInput = {
  name?: string;
  slug?: string;
  status?: AccountStatus;
};

export type AssignUserInput = {
  userId: string;
  role: AccountRole;
};

function slugify(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 120);
}

function serializeAccount(
  account: AccountListItem,
  viewer: AuthUser
) {
  const membership = account.memberships.find(
    (item) => item.userId === viewer.id
  );

  return {
    id: account.id,
    name: account.name,
    slug: account.slug,
    status: account.status,
    createdAt: account.createdAt,
    updatedAt: account.updatedAt,
    memberCount: account._count.memberships,
    viewerRole: isSuperAdmin(viewer) ? null : (membership?.role ?? null)
  };
}

function serializeAccountDetail(
  account: AccountDetail,
  viewer: AuthUser
) {
  const membership = account.memberships.find(
    (item) => item.user.id === viewer.id
  );

  return {
    id: account.id,
    name: account.name,
    slug: account.slug,
    status: account.status,
    createdAt: account.createdAt,
    updatedAt: account.updatedAt,
    viewerRole: isSuperAdmin(viewer) ? null : (membership?.role ?? null),
    users: account.memberships.map((membershipItem) => ({
      id: membershipItem.id,
      role: membershipItem.role,
      createdAt: membershipItem.createdAt,
      updatedAt: membershipItem.updatedAt,
      user: membershipItem.user
    })),
    auditLogs: account.auditLogs.map((entry) => ({
      id: entry.id,
      accountId: entry.accountId,
      actorUserId: entry.actorUserId,
      action: entry.action,
      entityType: entry.entityType,
      entityId: entry.entityId,
      before: entry.before,
      after: entry.after,
      createdAt: entry.createdAt
    }))
  };
}

@Injectable()
export class AccountsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService
  ) {}

  async createAccount(
    viewer: AuthUser,
    input: CreateAccountInput,
    sourceIp?: string
  ) {
    requireSuperAdmin(viewer);

    const name = input.name.trim();
    const slug = await this.createUniqueSlug(input.slug ?? name);

    const account = await this.prisma.account.create({
      data: {
        name,
        slug,
        createdById: viewer.id
      },
      include: accountListInclude
    });

    await this.audit.log({
      accountId: account.id,
      actorUserId: viewer.id,
      action: "ACCOUNT_CREATED",
      entityType: "account",
      entityId: account.id,
      after: { name: account.name, slug: account.slug, status: account.status },
      sourceIp
    });

    return serializeAccount(account, viewer);
  }

  async listAccounts(viewer: AuthUser) {
    const where: Prisma.AccountWhereInput = {
      deletedAt: null,
      status: { not: AccountStatus.DELETED }
    };

    if (!isSuperAdmin(viewer)) {
      where.memberships = { some: { userId: viewer.id } };
    }

    const accounts = await this.prisma.account.findMany({
      where,
      include: accountListInclude,
      orderBy: { createdAt: "desc" }
    });

    return accounts.map((account) => serializeAccount(account, viewer));
  }

  async getAccount(viewer: AuthUser, accountId: string) {
    const account = await this.findAccessibleAccount(viewer, accountId);
    return serializeAccountDetail(account, viewer);
  }

  async updateAccount(
    viewer: AuthUser,
    accountId: string,
    input: UpdateAccountInput,
    sourceIp?: string
  ) {
    requireSuperAdmin(viewer);

    const current = await this.getExistingAccount(accountId);
    const data: Prisma.AccountUpdateInput = {};

    if (input.name !== undefined) {
      data.name = input.name.trim();
    }

    if (input.slug !== undefined) {
      data.slug = await this.createUniqueSlug(input.slug, accountId);
    }

    if (input.status !== undefined) {
      data.status = input.status;
    }

    const updated = await this.prisma.account.update({
      where: { id: accountId },
      data,
      include: accountListInclude
    });

    await this.audit.log({
      accountId,
      actorUserId: viewer.id,
      action: "ACCOUNT_UPDATED",
      entityType: "account",
      entityId: accountId,
      before: {
        name: current.name,
        slug: current.slug,
        status: current.status
      },
      after: {
        name: updated.name,
        slug: updated.slug,
        status: updated.status
      },
      sourceIp
    });

    return serializeAccount(updated, viewer);
  }

  async suspendAccount(
    viewer: AuthUser,
    accountId: string,
    sourceIp?: string
  ) {
    requireSuperAdmin(viewer);

    const current = await this.getExistingAccount(accountId);
    const updated = await this.prisma.account.update({
      where: { id: accountId },
      data: { status: AccountStatus.SUSPENDED },
      include: accountListInclude
    });

    await this.audit.log({
      accountId,
      actorUserId: viewer.id,
      action: "ACCOUNT_SUSPENDED",
      entityType: "account",
      entityId: accountId,
      before: { status: current.status },
      after: { status: updated.status },
      sourceIp
    });

    return serializeAccount(updated, viewer);
  }

  async assignUser(
    viewer: AuthUser,
    accountId: string,
    input: AssignUserInput,
    sourceIp?: string
  ) {
    requireSuperAdmin(viewer);
    await this.getExistingAccount(accountId);

    const user = await this.prisma.user.findFirst({
      where: {
        id: input.userId,
        deletedAt: null
      },
      select: { id: true, email: true, username: true, displayName: true }
    });

    if (!user) {
      throw new BadRequestException("User does not exist");
    }

    const existing = await this.prisma.userAccount.findUnique({
      where: {
        userId_accountId: {
          userId: input.userId,
          accountId
        }
      }
    });

    const assignment = await this.prisma.userAccount.upsert({
      where: {
        userId_accountId: {
          userId: input.userId,
          accountId
        }
      },
      create: {
        userId: input.userId,
        accountId,
        role: input.role
      },
      update: {
        role: input.role
      }
    });

    await this.audit.log({
      accountId,
      actorUserId: viewer.id,
      action: existing ? "USER_ROLE_UPDATED" : "USER_ASSIGNED",
      entityType: "user_account",
      entityId: assignment.id,
      before: existing
        ? { userId: existing.userId, role: existing.role }
        : undefined,
      after: { userId: assignment.userId, role: assignment.role },
      sourceIp
    });

    return this.getAccount(viewer, accountId);
  }

  private async getExistingAccount(accountId: string) {
    const account = await this.prisma.account.findFirst({
      where: {
        id: accountId,
        deletedAt: null,
        status: { not: AccountStatus.DELETED }
      }
    });

    if (!account) {
      throw new NotFoundException("Account not found");
    }

    return account;
  }

  private async findAccessibleAccount(viewer: AuthUser, accountId: string) {
    const where: Prisma.AccountWhereInput = {
      id: accountId,
      deletedAt: null,
      status: { not: AccountStatus.DELETED }
    };

    if (viewer.globalRole !== GlobalRole.SUPER_ADMIN) {
      where.memberships = { some: { userId: viewer.id } };
    }

    const account = await this.prisma.account.findFirst({
      where,
      include: accountDetailInclude
    });

    if (!account) {
      throw new NotFoundException("Account not found");
    }

    return account;
  }

  private async createUniqueSlug(
    rawValue: string,
    ignoreAccountId?: string
  ): Promise<string> {
    const baseSlug = slugify(rawValue);

    if (!baseSlug) {
      throw new BadRequestException("Slug must contain a letter or number");
    }

    for (let index = 0; index < 50; index += 1) {
      const candidate = index === 0 ? baseSlug : `${baseSlug}-${index + 1}`;
      const existing = await this.prisma.account.findUnique({
        where: { slug: candidate },
        select: { id: true }
      });

      if (!existing || existing.id === ignoreAccountId) {
        return candidate;
      }
    }

    throw new ConflictException("Could not create a unique account slug");
  }
}

