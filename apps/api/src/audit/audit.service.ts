import { Injectable } from "@nestjs/common";
import { Prisma } from "@prisma/client";
import { sanitizeForStorage } from "../common/data-sanitizer";
import { PrismaService } from "../prisma/prisma.service";

type AuditLogInput = {
  accountId?: string | null;
  actorUserId?: string | null;
  action: string;
  entityType: string;
  entityId?: string | null;
  before?: unknown;
  after?: unknown;
  sourceIp?: string;
};

function toJson(value: unknown): Prisma.InputJsonValue | undefined {
  if (value === undefined) {
    return undefined;
  }

  return sanitizeForStorage(value);
}

@Injectable()
export class AuditService {
  constructor(private readonly prisma: PrismaService) {}

  async log(input: AuditLogInput): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        accountId: input.accountId,
        actorUserId: input.actorUserId,
        action: input.action,
        entityType: input.entityType,
        entityId: input.entityId,
        before: toJson(input.before),
        after: toJson(input.after),
        sourceIp: input.sourceIp
      }
    });
  }
}
