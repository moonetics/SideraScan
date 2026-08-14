import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Post,
  Req,
  UseGuards
} from "@nestjs/common";
import { DeviceMarkScope, DeviceMarkStatus } from "@prisma/client";
import { z } from "zod";
import { getRequestUser } from "../auth/authz";
import { SessionAuthGuard } from "../auth/session-auth.guard";
import type { AuthenticatedRequest } from "../auth/auth.types";
import { DevicesService } from "./devices.service";

const markSchema = z
  .object({
    status: z.enum(DeviceMarkStatus),
    scope: z.enum(DeviceMarkScope),
    accountId: z.string().uuid().optional(),
    reason: z.string().trim().min(3).max(2000),
    expiresAt: z
      .string()
      .datetime()
      .nullable()
      .optional()
      .transform((value) => (value ? new Date(value) : undefined)),
    evidenceScanSessionId: z.string().uuid().optional(),
    evidenceFindingId: z.string().uuid().optional(),
    note: z.string().trim().max(1000).optional()
  })
  .refine((value) => value.scope !== DeviceMarkScope.ACCOUNT || value.accountId, {
    message: "Account scoped marks require accountId"
  });

const updateMarkSchema = z
  .object({
    status: z.enum(DeviceMarkStatus).optional(),
    reason: z.string().trim().min(3).max(2000).optional(),
    expiresAt: z
      .string()
      .datetime()
      .nullable()
      .optional()
      .transform((value) =>
        value === undefined ? undefined : value ? new Date(value) : null
      )
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: "At least one mark field is required"
  });

const revokeMarkSchema = z.object({
  reason: z.string().trim().min(3).max(2000)
});

function parseBody<T>(schema: z.ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);

  if (!parsed.success) {
    throw new BadRequestException("Invalid request payload");
  }

  return parsed.data;
}

@Controller()
@UseGuards(SessionAuthGuard)
export class DevicesController {
  constructor(private readonly devicesService: DevicesService) {}

  @Get("devices")
  listDevices(@Req() request: AuthenticatedRequest) {
    return this.devicesService.listDevices(getRequestUser(request));
  }

  @Get("devices/:id")
  getDevice(@Req() request: AuthenticatedRequest, @Param("id") deviceId: string) {
    return this.devicesService.getDevice(getRequestUser(request), deviceId);
  }

  @Get("devices/:id/scans")
  getDeviceScans(
    @Req() request: AuthenticatedRequest,
    @Param("id") deviceId: string
  ) {
    return this.devicesService.getDeviceScans(
      getRequestUser(request),
      deviceId
    );
  }

  @Post("devices/:id/marks")
  createMark(
    @Req() request: AuthenticatedRequest,
    @Param("id") deviceId: string,
    @Body() body: unknown
  ) {
    return this.devicesService.createMark(
      getRequestUser(request),
      deviceId,
      parseBody(markSchema, body),
      request.ip
    );
  }

  @Patch("device-marks/:id")
  updateMark(
    @Req() request: AuthenticatedRequest,
    @Param("id") markId: string,
    @Body() body: unknown
  ) {
    return this.devicesService.updateMark(
      getRequestUser(request),
      markId,
      parseBody(updateMarkSchema, body),
      request.ip
    );
  }

  @Post("device-marks/:id/revoke")
  revokeMark(
    @Req() request: AuthenticatedRequest,
    @Param("id") markId: string,
    @Body() body: unknown
  ) {
    return this.devicesService.revokeMark(
      getRequestUser(request),
      markId,
      parseBody(revokeMarkSchema, body).reason,
      request.ip
    );
  }
}
