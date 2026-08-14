import { ForbiddenException, UnauthorizedException } from "@nestjs/common";
import { AccountRole, GlobalRole } from "@prisma/client";
import type { AuthenticatedRequest, AuthUser } from "./auth.types";

export function getRequestUser(request: AuthenticatedRequest): AuthUser {
  if (!request.user) {
    throw new UnauthorizedException();
  }

  return request.user;
}

export function isSuperAdmin(user: AuthUser): boolean {
  return user.globalRole === GlobalRole.SUPER_ADMIN;
}

export function requireSuperAdmin(user: AuthUser): void {
  if (!isSuperAdmin(user)) {
    throw new ForbiddenException("Super Admin access required");
  }
}

export function canManageAccountRole(role: AccountRole | null | undefined) {
  return role === AccountRole.ACCOUNT_OWNER;
}

export function canModerateAccountRole(role: AccountRole | null | undefined) {
  return (
    role === AccountRole.ACCOUNT_OWNER || role === AccountRole.MODERATOR
  );
}

export function canExportScanRole(role: AccountRole | null | undefined) {
  return canModerateAccountRole(role);
}
