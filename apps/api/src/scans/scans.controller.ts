import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Post,
  Query,
  Req,
  Res,
  UseGuards
} from "@nestjs/common";
import type { FastifyReply } from "fastify";
import { FindingCategory, Severity } from "@prisma/client";
import { z } from "zod";
import { getRequestUser } from "../auth/authz";
import { SessionAuthGuard } from "../auth/session-auth.guard";
import type { AuthenticatedRequest } from "../auth/auth.types";
import { ScanReviewsService } from "../scan-reviews/scan-reviews.service";
import { ScansService } from "./scans.service";

const findingsQuerySchema = z.object({
  q: z.string().trim().max(200).optional(),
  severity: z.enum(Severity).optional(),
  category: z.enum(FindingCategory).optional(),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  sort: z
    .enum(["createdAt", "severity", "category", "title", "confidence"])
    .default("createdAt"),
  direction: z.enum(["asc", "desc"]).default("desc")
});

const updateScanSchema = z.object({
  playerLabel: z
    .string()
    .trim()
    .max(160)
    .nullable()
    .optional()
    .transform((value) => (value === "" ? null : value))
});

function parseQuery(query: unknown) {
  const parsed = findingsQuerySchema.safeParse(query);

  if (!parsed.success) {
    throw new BadRequestException("Invalid query");
  }

  return parsed.data;
}

@Controller("scans")
@UseGuards(SessionAuthGuard)
export class ScansController {
  constructor(
    private readonly scansService: ScansService,
    private readonly scanReviewsService: ScanReviewsService
  ) {}

  @Get()
  listScans(@Req() request: AuthenticatedRequest) {
    return this.scansService.listScans(getRequestUser(request));
  }

  @Get(":id/findings")
  listFindings(
    @Req() request: AuthenticatedRequest,
    @Param("id") scanId: string,
    @Query() query: unknown
  ) {
    return this.scansService.listFindings(
      getRequestUser(request),
      scanId,
      parseQuery(query)
    );
  }

  @Get(":id/export")
  async exportScan(
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: FastifyReply,
    @Param("id") scanId: string,
    @Query("format") format: "html" | "json" = "html"
  ) {
    if (format !== "html" && format !== "json") {
      throw new BadRequestException("Invalid export format");
    }

    const report = await this.scansService.exportScanReport(
      getRequestUser(request),
      scanId,
      format,
      request.ip
    );

    response.header("content-type", report.contentType);
    response.header(
      "content-disposition",
      `attachment; filename="${report.fileName}"`
    );

    return report.body;
  }

  @Get(":id")
  getScan(@Req() request: AuthenticatedRequest, @Param("id") scanId: string) {
    return this.scansService.getScan(getRequestUser(request), scanId);
  }

  @Patch(":id")
  updateScan(
    @Req() request: AuthenticatedRequest,
    @Param("id") scanId: string,
    @Body() body: unknown
  ) {
    const parsed = updateScanSchema.safeParse(body);

    if (!parsed.success) {
      throw new BadRequestException("Invalid request payload");
    }

    return this.scansService.updateScan(
      getRequestUser(request),
      scanId,
      parsed.data,
      request.ip
    );
  }

  @Post(":id/ai-review/retry")
  retryAiReview(
    @Req() request: AuthenticatedRequest,
    @Param("id") scanId: string
  ) {
    return this.scanReviewsService.retryScanReview(
      getRequestUser(request),
      scanId
    );
  }
}
