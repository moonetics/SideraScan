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
import { ExecutorIntelligenceService } from "./executor-intelligence.service";

const settingsSchema = z
  .object({
    enabled: z.boolean().optional(),
    sourceUrl: z.string().url().max(500).optional(),
    fallbackUrl: z.string().url().max(500).optional(),
    cacheTtlSeconds: z.number().int().min(60).max(604800).optional()
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: "At least one setting is required"
  });

function parseBody<T>(schema: z.ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);

  if (!parsed.success) {
    throw new BadRequestException("Invalid request payload");
  }

  return parsed.data;
}

@Controller("executor-intelligence")
@UseGuards(SessionAuthGuard)
export class ExecutorIntelligenceController {
  constructor(
    private readonly executorIntelligenceService: ExecutorIntelligenceService
  ) {}

  @Get()
  getOverview(@Req() request: AuthenticatedRequest) {
    return this.executorIntelligenceService.getOverview(
      getRequestUser(request),
      request.ip
    );
  }

  @Post("sync")
  sync(@Req() request: AuthenticatedRequest) {
    return this.executorIntelligenceService.sync(
      getRequestUser(request),
      request.ip
    );
  }

  @Patch("settings")
  updateSettings(@Req() request: AuthenticatedRequest, @Body() body: unknown) {
    return this.executorIntelligenceService.updateSettings(
      getRequestUser(request),
      parseBody(settingsSchema, body),
      request.ip
    );
  }
}
