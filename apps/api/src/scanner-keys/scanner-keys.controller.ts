import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Param,
  Post,
  Req,
  UseGuards
} from "@nestjs/common";
import { z } from "zod";
import { getRequestUser } from "../auth/authz";
import { SessionAuthGuard } from "../auth/session-auth.guard";
import type { AuthenticatedRequest } from "../auth/auth.types";
import { ScannerKeysService } from "./scanner-keys.service";

const createScannerKeySchema = z.object({
  name: z.string().trim().min(1).max(120),
  expiresAt: z
    .string()
    .datetime()
    .nullable()
    .optional()
    .transform((value) => (value ? new Date(value) : null)),
  rateLimitPerHour: z.coerce.number().int().min(1).max(10000).default(60),
  allowedScannerVersions: z.array(z.string().trim().min(1).max(40)).default([])
});

function parseBody<T>(schema: z.ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);

  if (!parsed.success) {
    throw new BadRequestException("Invalid request payload");
  }

  return parsed.data;
}

@UseGuards(SessionAuthGuard)
export class ScannerKeysControllerBase {
  constructor(protected readonly scannerKeysService: ScannerKeysService) {}
}

@Controller("scanner-keys")
@UseGuards(SessionAuthGuard)
export class ScannerKeysController extends ScannerKeysControllerBase {
  @Get()
  listVisibleKeys(@Req() request: AuthenticatedRequest) {
    return this.scannerKeysService.listVisibleKeys(getRequestUser(request));
  }

  @Post(":id/rotate")
  rotateKey(
    @Req() request: AuthenticatedRequest,
    @Param("id") scannerKeyId: string
  ) {
    return this.scannerKeysService.rotateKey(
      getRequestUser(request),
      scannerKeyId,
      request.ip
    );
  }

  @Post(":id/revoke")
  revokeKey(
    @Req() request: AuthenticatedRequest,
    @Param("id") scannerKeyId: string
  ) {
    return this.scannerKeysService.revokeKey(
      getRequestUser(request),
      scannerKeyId,
      request.ip
    );
  }
}

@Controller("accounts/:accountId/scanner-keys")
@UseGuards(SessionAuthGuard)
export class AccountScannerKeysController extends ScannerKeysControllerBase {
  @Get()
  listAccountKeys(
    @Req() request: AuthenticatedRequest,
    @Param("accountId") accountId: string
  ) {
    return this.scannerKeysService.listAccountKeys(
      getRequestUser(request),
      accountId
    );
  }

  @Post()
  createKey(
    @Req() request: AuthenticatedRequest,
    @Param("accountId") accountId: string,
    @Body() body: unknown
  ) {
    return this.scannerKeysService.createKey(
      getRequestUser(request),
      accountId,
      parseBody(createScannerKeySchema, body),
      request.ip
    );
  }
}
