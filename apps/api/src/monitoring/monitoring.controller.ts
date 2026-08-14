import {
  BadRequestException,
  Controller,
  Get,
  Param,
  Post,
  Query,
  Req,
  UseGuards
} from "@nestjs/common";
import { AlertNotificationStatus, MonitoringSeverity } from "@prisma/client";
import { z } from "zod";
import { getRequestUser } from "../auth/authz";
import type { AuthenticatedRequest } from "../auth/auth.types";
import { SessionAuthGuard } from "../auth/session-auth.guard";
import { MonitoringService } from "./monitoring.service";

const listQuerySchema = z.object({
  eventType: z.string().trim().max(120).optional(),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  q: z.string().trim().max(200).optional(),
  severity: z.enum(MonitoringSeverity).optional(),
  status: z.enum(AlertNotificationStatus).optional()
});

function parseQuery(query: unknown) {
  const parsed = listQuerySchema.safeParse(query);

  if (!parsed.success) {
    throw new BadRequestException("Invalid monitoring query");
  }

  return parsed.data;
}

@Controller("monitoring")
@UseGuards(SessionAuthGuard)
export class MonitoringController {
  constructor(private readonly monitoring: MonitoringService) {}

  @Get("overview")
  overview(@Req() request: AuthenticatedRequest) {
    return this.monitoring.overview(getRequestUser(request), request.ip);
  }

  @Get("security-events")
  securityEvents(
    @Req() request: AuthenticatedRequest,
    @Query() query: unknown
  ) {
    return this.monitoring.listSecurityEvents(
      getRequestUser(request),
      parseQuery(query),
      request.ip
    );
  }

  @Get("alerts")
  alerts(@Req() request: AuthenticatedRequest, @Query() query: unknown) {
    return this.monitoring.listAlerts(
      getRequestUser(request),
      parseQuery(query),
      request.ip
    );
  }

  @Post("alerts/:id/retry")
  retryAlert(
    @Req() request: AuthenticatedRequest,
    @Param("id") alertId: string
  ) {
    return this.monitoring.retryAlert(
      getRequestUser(request),
      alertId,
      request.ip
    );
  }
}
