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
import {
  DetectionRuleScope,
  DetectionRuleType,
  FindingCategory,
  Severity
} from "@prisma/client";
import { z } from "zod";
import { getRequestUser } from "../auth/authz";
import { SessionAuthGuard } from "../auth/session-auth.guard";
import type { AuthenticatedRequest } from "../auth/auth.types";
import { DetectionsService } from "./detections.service";

const processNameConfigSchema = z.object({
  processNames: z.array(z.string().trim().min(1).max(160)).min(1).max(100),
  matchMode: z.enum(["exact", "contains", "regex"])
});

const fileHashConfigSchema = z.object({
  hashes: z
    .array(z.string().trim().min(16).max(128).regex(/^[a-fA-F0-9]+$/))
    .min(1)
    .max(200),
  algorithm: z.literal("sha256")
});

const pathPatternConfigSchema = z.object({
  patterns: z.array(z.string().trim().min(1).max(500)).min(1).max(100),
  matchMode: z.enum(["contains", "glob", "regex"])
});

const stringSignatureConfigSchema = z.object({
  strings: z
    .array(
      z.object({
        valueHash: z.string().trim().min(16).max(128),
        preview: z.string().trim().min(1).max(180)
      })
    )
    .min(1)
    .max(100),
  targetProcessNames: z
    .array(z.string().trim().min(1).max(160))
    .max(50)
    .optional(),
  clientName: z.string().trim().max(120).optional()
});

const createRuleSchema = z
  .object({
    accountId: z.string().uuid().optional(),
    scope: z.enum(DetectionRuleScope),
    name: z.string().trim().min(2).max(160),
    type: z.enum(DetectionRuleType),
    category: z.enum(FindingCategory).default(FindingCategory.CUSTOM_DETECTION),
    severity: z.enum(Severity).default(Severity.WARNING),
    enabled: z.boolean().default(true),
    ruleConfig: z.unknown()
  })
  .superRefine((value, context) => {
    if (value.scope === DetectionRuleScope.ACCOUNT && !value.accountId) {
      context.addIssue({
        code: "custom",
        message: "Account scoped rules require accountId",
        path: ["accountId"]
      });
    }

    const schemaByType = {
      [DetectionRuleType.PROCESS_NAME]: processNameConfigSchema,
      [DetectionRuleType.FILE_HASH]: fileHashConfigSchema,
      [DetectionRuleType.PATH_PATTERN]: pathPatternConfigSchema,
      [DetectionRuleType.STRING_SIGNATURE]: stringSignatureConfigSchema
    };
    const parsed = schemaByType[value.type].safeParse(value.ruleConfig);

    if (!parsed.success) {
      context.addIssue({
        code: "custom",
        message: "Invalid ruleConfig for rule type",
        path: ["ruleConfig"]
      });
    }
  });

const updateRuleSchema = z
  .object({
    name: z.string().trim().min(2).max(160).optional(),
    category: z.enum(FindingCategory).optional(),
    severity: z.enum(Severity).optional(),
    enabled: z.boolean().optional(),
    ruleConfig: z.unknown().optional()
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: "At least one rule field is required"
  });

const sampleUploadSchema = z.object({
  accountId: z.string().uuid().optional(),
  fileName: z.string().trim().min(1).max(240),
  contentBase64: z.string().min(1)
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
export class DetectionsController {
  constructor(private readonly detectionsService: DetectionsService) {}

  @Get("detection-rules")
  listRules(@Req() request: AuthenticatedRequest) {
    return this.detectionsService.listRules(getRequestUser(request));
  }

  @Post("detection-rules")
  createRule(@Req() request: AuthenticatedRequest, @Body() body: unknown) {
    return this.detectionsService.createRule(
      getRequestUser(request),
      parseBody(createRuleSchema, body),
      request.ip
    );
  }

  @Patch("detection-rules/:id")
  updateRule(
    @Req() request: AuthenticatedRequest,
    @Param("id") ruleId: string,
    @Body() body: unknown
  ) {
    return this.detectionsService.updateRule(
      getRequestUser(request),
      ruleId,
      parseBody(updateRuleSchema, body),
      request.ip
    );
  }

  @Post("detection-rules/:id/disable")
  disableRule(@Req() request: AuthenticatedRequest, @Param("id") ruleId: string) {
    return this.detectionsService.disableRule(
      getRequestUser(request),
      ruleId,
      request.ip
    );
  }

  @Post("detection-samples/upload")
  uploadSample(@Req() request: AuthenticatedRequest, @Body() body: unknown) {
    return this.detectionsService.uploadSample(
      getRequestUser(request),
      parseBody(sampleUploadSchema, body),
      request.ip
    );
  }

  @Get("detection-samples/:id/strings")
  getSampleStrings(
    @Req() request: AuthenticatedRequest,
    @Param("id") sampleId: string
  ) {
    return this.detectionsService.getSampleStrings(
      getRequestUser(request),
      sampleId
    );
  }
}
