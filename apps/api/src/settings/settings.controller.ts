import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Patch,
  Post,
  Req,
  UseGuards
} from "@nestjs/common";
import { z } from "zod";
import { getRequestUser } from "../auth/authz";
import type { AuthenticatedRequest } from "../auth/auth.types";
import { SessionAuthGuard } from "../auth/session-auth.guard";
import { SettingsService } from "./settings.service";

const retentionSchema = z
  .object({
    scanResultsDays: z.coerce.number().int().min(1).max(3650).optional(),
    findingsEvidenceDays: z.coerce.number().int().min(1).max(3650).optional(),
    screenshotsDays: z.coerce.number().int().min(1).max(3650).optional(),
    detectionSamplesDays: z.coerce.number().int().min(1).max(3650).optional(),
    monitoringEventsDays: z.coerce.number().int().min(1).max(3650).optional(),
    securityEventsDays: z.coerce.number().int().min(1).max(3650).optional(),
    auditLogsDays: z.coerce.number().int().min(1).max(3650).optional()
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: "At least one retention field is required"
  });

function parseBody<T>(schema: z.ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);

  if (!parsed.success) {
    throw new BadRequestException("Invalid request payload");
  }

  return parsed.data;
}

@Controller("settings")
@UseGuards(SessionAuthGuard)
export class SettingsController {
  constructor(private readonly settings: SettingsService) {}

  @Get("retention")
  getRetention(@Req() request: AuthenticatedRequest) {
    return this.settings.getRetention(getRequestUser(request), request.ip);
  }

  @Patch("retention")
  updateRetention(@Req() request: AuthenticatedRequest, @Body() body: unknown) {
    return this.settings.updateRetention(
      getRequestUser(request),
      parseBody(retentionSchema, body),
      request.ip
    );
  }

  @Post("retention/dry-run")
  dryRun(@Req() request: AuthenticatedRequest) {
    return this.settings.retentionDryRun(getRequestUser(request), request.ip);
  }
}
