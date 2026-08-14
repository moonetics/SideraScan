import { BadRequestException, Body, Controller, Post, Req } from "@nestjs/common";
import { AiRecommendedAction, MonitoringSeverity } from "@prisma/client";
import type { FastifyRequest } from "fastify";
import { z } from "zod";
import { MonitoringService } from "../monitoring/monitoring.service";
import { assertValidN8nSignature } from "./scan-review-signature";
import {
  rejectAutoBanAction,
  ScanReviewsService
} from "./scan-reviews.service";

const evidenceReferenceSchema = z.object({
  findingId: z.string().uuid().optional(),
  evidenceId: z.string().uuid().optional(),
  label: z.string().trim().max(160).optional(),
  note: z.string().trim().max(500).optional()
});

const aiReviewSchema = z.object({
  scanSessionId: z.string().uuid(),
  assessment: z.string().trim().min(1).max(80),
  confidence: z.coerce.number().int().min(0).max(100),
  summaryForModerator: z.string().trim().min(1).max(5000),
  summaryForPlayer: z.string().trim().max(5000).optional(),
  recommendedAction: z.enum(AiRecommendedAction),
  keyIndicators: z.array(z.unknown()).default([]),
  possibleFalsePositives: z.array(z.unknown()).default([]),
  contradictions: z.array(z.unknown()).default([]),
  moderatorChecklist: z.array(z.unknown()).default([]),
  questionsForPlayer: z.array(z.unknown()).default([]),
  evidenceReferences: z.array(evidenceReferenceSchema).default([]),
  model: z.string().trim().max(120).optional(),
  promptVersion: z.string().trim().max(80).optional(),
  inputHash: z.string().trim().max(128).optional(),
  generatedAt: z
    .string()
    .datetime()
    .optional()
    .transform((value) => (value ? new Date(value) : new Date()))
});

@Controller("scan-reviews")
export class ScanReviewsController {
  constructor(
    private readonly scanReviewsService: ScanReviewsService,
    private readonly monitoring: MonitoringService
  ) {}

  @Post()
  async submitReview(@Body() body: unknown, @Req() request: FastifyRequest) {
    try {
      assertValidN8nSignature(request, body);
    } catch (error) {
      await this.monitoring.recordSecurityEvent({
        eventType: "N8N_SIGNATURE_INVALID",
        message: "Invalid n8n AI review callback signature.",
        metadata: { route: "/scan-reviews" },
        severity: MonitoringSeverity.HIGH,
        sourceIp: request.ip
      });

      throw error;
    }

    const result = aiReviewSchema.safeParse(body);

    if (!result.success) {
      throw new BadRequestException("Invalid AI review payload");
    }

    const parsed = result.data;
    rejectAutoBanAction(parsed.recommendedAction);

    return this.scanReviewsService.submitAiReview(parsed);
  }
}
