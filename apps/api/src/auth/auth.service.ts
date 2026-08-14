import { Injectable, UnauthorizedException } from "@nestjs/common";
import { GlobalRole, Prisma, UserStatus } from "@prisma/client";
import * as argon2 from "argon2";
import type { JWTPayload } from "jose";
import { env } from "../config/env";
import { PrismaService } from "../prisma/prisma.service";
import type { AuthUser } from "./auth.types";

const userSelect = {
  id: true,
  email: true,
  username: true,
  passwordHash: true,
  displayName: true,
  globalRole: true,
  status: true
} satisfies Prisma.UserSelect;

type UserWithPassword = Prisma.UserGetPayload<{ select: typeof userSelect }>;
type JoseModule = typeof import("jose");

function toAuthUser(user: UserWithPassword): AuthUser {
  return {
    id: user.id,
    email: user.email,
    username: user.username,
    displayName: user.displayName,
    globalRole: user.globalRole,
    status: user.status
  };
}

async function loadJose(): Promise<JoseModule> {
  return import("jose");
}

@Injectable()
export class AuthService {
  private readonly secret = new TextEncoder().encode(env.AUTH_SECRET);

  constructor(private readonly prisma: PrismaService) {}

  async login(
    identifier: string,
    password: string
  ): Promise<{ token: string; user: AuthUser }> {
    const normalizedIdentifier = identifier.trim().toLowerCase();
    const user = await this.prisma.user.findFirst({
      where: {
        deletedAt: null,
        OR: [
          { email: normalizedIdentifier },
          { username: normalizedIdentifier }
        ]
      },
      select: userSelect
    });

    if (!user || user.status !== UserStatus.ACTIVE) {
      throw new UnauthorizedException("Invalid credentials");
    }

    const isValidPassword = await argon2.verify(user.passwordHash, password);

    if (!isValidPassword) {
      throw new UnauthorizedException("Invalid credentials");
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() }
    });

    return {
      token: await this.createSessionToken(user.id, user.globalRole),
      user: toAuthUser(user)
    };
  }

  async getUserFromSession(token: string): Promise<AuthUser> {
    const { jwtVerify } = await loadJose();
    let payload: JWTPayload;

    try {
      const verified = await jwtVerify(token, this.secret);
      payload = verified.payload;
    } catch {
      throw new UnauthorizedException();
    }

    if (!payload.sub) {
      throw new UnauthorizedException();
    }

    const user = await this.prisma.user.findFirst({
      where: {
        id: payload.sub,
        status: UserStatus.ACTIVE,
        deletedAt: null
      },
      select: userSelect
    });

    if (!user) {
      throw new UnauthorizedException();
    }

    return toAuthUser(user);
  }

  private async createSessionToken(
    userId: string,
    globalRole: GlobalRole
  ): Promise<string> {
    const { SignJWT } = await loadJose();
    const now = Math.floor(Date.now() / 1000);

    return new SignJWT({ globalRole })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject(userId)
      .setIssuedAt(now)
      .setExpirationTime(now + env.SESSION_TTL_SECONDS)
      .sign(this.secret);
  }
}
