import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException
} from "@nestjs/common";
import { GlobalRole, Prisma, UserStatus } from "@prisma/client";
import * as argon2 from "argon2";
import { AuditService } from "../audit/audit.service";
import { requireSuperAdmin } from "../auth/authz";
import type { AuthUser } from "../auth/auth.types";
import { PrismaService } from "../prisma/prisma.service";

const safeUserSelect = {
  id: true,
  email: true,
  username: true,
  displayName: true,
  globalRole: true,
  status: true,
  lastLoginAt: true,
  createdAt: true,
  updatedAt: true,
  accountMemberships: {
    where: {
      account: {
        deletedAt: null
      }
    },
    select: {
      id: true,
      role: true,
      accountId: true,
      createdAt: true,
      account: {
        select: {
          id: true,
          name: true,
          slug: true,
          status: true
        }
      }
    },
    orderBy: {
      createdAt: "desc"
    }
  }
} satisfies Prisma.UserSelect;

type SafeUser = Prisma.UserGetPayload<{ select: typeof safeUserSelect }>;

export type CreateUserInput = {
  email: string;
  username: string;
  displayName: string;
  password: string;
  globalRole?: GlobalRole;
  status?: UserStatus;
};

export type UpdateUserInput = {
  email?: string;
  username?: string;
  displayName?: string;
  globalRole?: GlobalRole;
  status?: UserStatus;
  password?: string;
};

function serializeUser(user: SafeUser) {
  return {
    id: user.id,
    email: user.email,
    username: user.username,
    displayName: user.displayName,
    globalRole: user.globalRole,
    status: user.status,
    lastLoginAt: user.lastLoginAt,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    accountMemberships: user.accountMemberships.map((membership) => ({
      id: membership.id,
      accountId: membership.accountId,
      role: membership.role,
      createdAt: membership.createdAt,
      account: membership.account
    })),
    accountMembershipCount: user.accountMemberships.length,
    isAssigned: user.accountMemberships.length > 0
  };
}

@Injectable()
export class UsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService
  ) {}

  async createUser(
    viewer: AuthUser,
    input: CreateUserInput,
    sourceIp?: string
  ) {
    requireSuperAdmin(viewer);

    const email = input.email.trim().toLowerCase();
    const username = input.username.trim().toLowerCase();
    const existing = await this.prisma.user.findFirst({
      where: {
        OR: [{ email }, { username }]
      },
      select: { id: true }
    });

    if (existing) {
      throw new ConflictException("Email or username already exists");
    }

    const passwordHash = await argon2.hash(input.password, {
      type: argon2.argon2id
    });

    const user = await this.prisma.user.create({
      data: {
        email,
        username,
        displayName: input.displayName.trim(),
        passwordHash,
        globalRole: input.globalRole ?? GlobalRole.USER,
        status: input.status ?? UserStatus.ACTIVE
      },
      select: safeUserSelect
    });

    await this.audit.log({
      actorUserId: viewer.id,
      action: "USER_CREATED",
      entityType: "user",
      entityId: user.id,
      after: {
        email: user.email,
        username: user.username,
        displayName: user.displayName,
        globalRole: user.globalRole,
        status: user.status
      },
      sourceIp
    });

    return serializeUser(user);
  }

  async listUsers(viewer: AuthUser) {
    requireSuperAdmin(viewer);

    const users = await this.prisma.user.findMany({
      where: {
        deletedAt: null
      },
      select: safeUserSelect,
      orderBy: { createdAt: "desc" }
    });

    return users.map(serializeUser);
  }

  async updateUser(
    viewer: AuthUser,
    userId: string,
    input: UpdateUserInput,
    sourceIp?: string
  ) {
    requireSuperAdmin(viewer);

    const current = await this.prisma.user.findFirst({
      where: {
        id: userId,
        deletedAt: null
      },
      select: {
        ...safeUserSelect,
        passwordHash: true
      }
    });

    if (!current) {
      throw new NotFoundException("User not found");
    }

    const data: Prisma.UserUpdateInput = {};

    if (input.email !== undefined) {
      data.email = input.email.trim().toLowerCase();
    }

    if (input.username !== undefined) {
      data.username = input.username.trim().toLowerCase();
    }

    if (input.displayName !== undefined) {
      data.displayName = input.displayName.trim();
    }

    if (input.globalRole !== undefined) {
      data.globalRole = input.globalRole;
    }

    if (input.status !== undefined) {
      data.status = input.status;
    }

    if (input.password !== undefined) {
      data.passwordHash = await argon2.hash(input.password, {
        type: argon2.argon2id
      });
    }

    try {
      const updated = await this.prisma.user.update({
        where: { id: userId },
        data,
        select: safeUserSelect
      });

      await this.audit.log({
        actorUserId: viewer.id,
        action: "USER_UPDATED",
        entityType: "user",
        entityId: userId,
        before: {
          email: current.email,
          username: current.username,
          displayName: current.displayName,
          globalRole: current.globalRole,
          status: current.status
        },
        after: {
          email: updated.email,
          username: updated.username,
          displayName: updated.displayName,
          globalRole: updated.globalRole,
          status: updated.status
        },
        sourceIp
      });

      return serializeUser(updated);
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === "P2002"
      ) {
        throw new ConflictException("Email or username already exists");
      }

      throw error;
    }
  }

  async disableUser(viewer: AuthUser, userId: string, sourceIp?: string) {
    if (viewer.id === userId) {
      throw new BadRequestException("Super Admin cannot disable their own user");
    }

    return this.updateUser(
      viewer,
      userId,
      { status: UserStatus.DISABLED },
      sourceIp
    );
  }
}
