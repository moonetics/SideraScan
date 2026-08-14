import {
  BadRequestException,
  Body,
  Controller,
  Param,
  Post,
  Req
} from "@nestjs/common";
import { FindingCategory, FingerprintConfidence, Severity } from "@prisma/client";
import type { FastifyRequest } from "fastify";
import { z } from "zod";
import { DetectionsService } from "../detections/detections.service";
import { ScannerService } from "./scanner.service";

const validateKeySchema = z.object({
  scannerKey: z.string().trim().min(1),
  scannerVersion: z.string().trim().min(1).max(40),
  platform: z.string().trim().min(1).max(40),
  arch: z.string().trim().min(1).max(40),
  playerLabel: z.string().trim().max(160).optional()
});

const confidenceSchema = z.coerce
  .number()
  .min(0)
  .max(100)
  .transform((value) =>
    value > 0 && value <= 1 ? Math.round(value * 100) : Math.round(value)
  );

const findingSchema = z.object({
  category: z.enum(FindingCategory).optional(),
  severity: z.enum(Severity).optional(),
  title: z.string().trim().min(1).max(200),
  message: z.string().trim().min(1).max(2000),
  ruleId: z.string().uuid().optional(),
  confidence: confidenceSchema.optional(),
  sourceModule: z.string().trim().max(80).optional(),
  evidenceRef: z.string().trim().max(120).optional(),
  metadata: z.unknown().optional()
});

const moduleSchema = z.object({
  moduleName: z.string().trim().min(1).max(80),
  status: z.string().trim().min(1).max(24),
  durationMs: z.coerce.number().int().min(0).optional(),
  errorCode: z.string().trim().max(80).optional(),
  errorMessage: z.string().trim().max(500).optional()
});

const evidenceSchema = z.object({
  clientEvidenceId: z.string().trim().max(120).optional(),
  type: z.string().trim().min(1).max(80),
  title: z.string().trim().min(1).max(200),
  data: z.unknown().optional(),
  storageRef: z.string().trim().max(500).optional()
});

const dateSchema = z
  .string()
  .datetime()
  .optional()
  .transform((value) => (value ? new Date(value) : undefined));

const launcherProfileSchema = z.object({
  profileName: z.string().trim().min(1).max(160),
  launcherType: z.string().trim().min(1).max(80),
  version: z.string().trim().max(80).optional(),
  channel: z.string().trim().max(80).optional(),
  path: z.string().trim().max(500).optional(),
  executableHash: z.string().trim().max(128).optional(),
  publisher: z.string().trim().max(160).optional(),
  status: z.string().trim().max(40).optional(),
  tags: z.array(z.unknown()).default([]),
  installTime: dateSchema,
  updateTime: dateSchema,
  lastLaunchTime: dateSchema,
  metadata: z.unknown().optional()
});

const clientModAssetSchema = z.object({
  name: z.string().trim().min(1).max(160),
  sourceLauncher: z.string().trim().max(160).optional(),
  path: z.string().trim().max(500).optional(),
  fileCount: z.coerce.number().int().min(0).optional(),
  totalSize: z.coerce.number().int().min(0).optional(),
  createdTime: dateSchema,
  modifiedTime: dateSchema,
  status: z.string().trim().max(40).optional(),
  metadata: z.unknown().optional()
});

const processTimeSchema = z.object({
  processName: z.string().trim().min(1).max(160),
  path: z.string().trim().max(500).optional(),
  firstSeenAt: dateSchema,
  lastSeenAt: dateSchema,
  startedAt: dateSchema,
  endedAt: dateSchema,
  durationMs: z.coerce.number().int().min(0).optional(),
  source: z.string().trim().max(80).optional(),
  status: z.string().trim().max(40).optional(),
  metadata: z.unknown().optional()
});

const fileLogSchema = z.object({
  action: z.string().trim().min(1).max(80),
  path: z.string().trim().max(500).optional(),
  oldPath: z.string().trim().max(500).optional(),
  newPath: z.string().trim().max(500).optional(),
  timestamp: dateSchema,
  source: z.string().trim().max(120).optional(),
  confidence: confidenceSchema.optional(),
  relatedProcess: z.string().trim().max(160).optional(),
  severity: z.enum(Severity).optional(),
  metadata: z.unknown().optional()
});

const forensicArraySchema = z.array(z.unknown()).default([]);

const deviceFingerprintSchema = z.object({
  hash: z
    .string()
    .trim()
    .min(16)
    .max(128)
    .regex(/^[A-Za-z0-9:_-]+$/),
  version: z.string().trim().min(1).max(40).default("v1"),
  confidence: z.enum(FingerprintConfidence).default(FingerprintConfidence.MEDIUM)
});

const resultSchema = z.object({
  uploadToken: z.string().min(1),
  nonce: z.string().min(1),
  accountId: z.string().optional(),
  scannerVersion: z.string().optional(),
  startedAt: z.string().datetime().optional().transform((value) => value ? new Date(value) : undefined),
  finishedAt: z.string().datetime().optional().transform((value) => value ? new Date(value) : undefined),
  overview: z.unknown().optional(),
  systemIdentity: z.unknown().optional(),
  networkSnapshot: z.unknown().optional(),
  integrity: z.unknown().optional(),
  modules: z.array(moduleSchema).default([]),
  evidence: z.array(evidenceSchema).default([]),
  processTimeline: z.unknown().optional(),
  exploreFiles: z.unknown().optional(),
  utilities: z.unknown().optional(),
  windowsItems: z.unknown().optional(),
  auditLog: z.unknown().optional(),
  deviceFingerprint: deviceFingerprintSchema.optional(),
  device_fingerprint: deviceFingerprintSchema.optional(),
  launcherProfiles: z.array(launcherProfileSchema).default([]),
  clientModAssets: z.array(clientModAssetSchema).default([]),
  processTimes: z.array(processTimeSchema).default([]),
  fileLogs: z.array(fileLogSchema).default([]),
  loadedModules: forensicArraySchema,
  processHandles: forensicArraySchema,
  services: forensicArraySchema,
  drivers: forensicArraySchema,
  persistenceItems: forensicArraySchema,
  eventLogs: forensicArraySchema,
  defenderEvents: forensicArraySchema,
  executionArtifacts: forensicArraySchema,
  fileTriage: forensicArraySchema,
  networkConnections: forensicArraySchema,
  dnsCache: forensicArraySchema,
  hostsEntries: forensicArraySchema,
  forensicTimeline: forensicArraySchema,
  findings: z.array(findingSchema).default([]),
  indicationLogs: z.array(findingSchema).default([])
});

const chunkedResultSectionSchema = z.enum([
  "processTimeline",
  "exploreFiles",
  "utilities",
  "windowsItems",
  "launcherProfiles",
  "clientModAssets",
  "processTimes",
  "fileLogs",
  "loadedModules",
  "processHandles",
  "services",
  "drivers",
  "persistenceItems",
  "eventLogs",
  "defenderEvents",
  "executionArtifacts",
  "fileTriage",
  "networkConnections",
  "dnsCache",
  "hostsEntries",
  "forensicTimeline"
]);

const resultSectionSchema = z
  .object({
    uploadToken: z.string().min(1),
    nonce: z.string().min(1),
    section: chunkedResultSectionSchema,
    items: z.array(z.unknown()).optional(),
    data: z.unknown().optional(),
    totalItems: z.coerce.number().int().min(0).optional(),
    chunkIndex: z.coerce.number().int().min(0).default(0),
    chunkCount: z.coerce.number().int().min(1).default(1),
    payloadHash: z.string().trim().max(128).optional(),
    status: z.enum(["uploaded", "failed"]).default("uploaded"),
    errorCode: z.string().trim().max(80).optional()
  })
  .refine((value) => value.status === "failed" || value.items !== undefined || value.data !== undefined, {
    message: "items or data is required for uploaded sections"
  });

const completeTelemetrySchema = z.object({
  uploadDurationMs: z.coerce.number().int().min(0).optional(),
  uploadAttemptCount: z.coerce.number().int().min(0).optional(),
  completeAttemptCount: z.coerce.number().int().min(0).optional(),
  lastErrorCode: z.string().trim().max(80).optional(),
  scannerVersion: z.string().trim().max(40).optional()
});

const completeSchema = z.object({
  uploadToken: z.string().min(1),
  nonce: z.string().min(1),
  status: z.enum(["COMPLETED", "FAILED", "PARTIAL"]).optional(),
  telemetry: completeTelemetrySchema.optional()
});

const scannerConfigSchema = z.object({
  scannerKey: z.string().trim().min(1),
  scannerVersion: z.string().trim().min(1).max(40)
});

function parseBody<T>(schema: z.ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);

  if (!parsed.success) {
    throw new BadRequestException("Invalid request payload");
  }

  return parsed.data;
}

@Controller("scanner")
export class ScannerController {
  constructor(
    private readonly scannerService: ScannerService,
    private readonly detectionsService: DetectionsService
  ) {}

  @Post("validate-key")
  validateKey(@Body() body: unknown, @Req() request: FastifyRequest) {
    return this.scannerService.validateKey(
      parseBody(validateKeySchema, body),
      request.ip
    );
  }

  @Post("config")
  getScannerConfig(@Body() body: unknown) {
    return this.detectionsService.getScannerConfig(
      parseBody(scannerConfigSchema, body)
    );
  }

  @Post("sessions/:id/results")
  saveResults(
    @Param("id") scanSessionId: string,
    @Body() body: unknown,
    @Req() request: FastifyRequest
  ) {
    return this.scannerService.saveResults(
      scanSessionId,
      parseBody(resultSchema, body),
      request.ip
    );
  }

  @Post("sessions/:id/results/core")
  saveResultsCore(
    @Param("id") scanSessionId: string,
    @Body() body: unknown,
    @Req() request: FastifyRequest
  ) {
    return this.scannerService.saveResultsCore(
      scanSessionId,
      parseBody(resultSchema, body),
      request.ip
    );
  }

  @Post("sessions/:id/results/section")
  saveResultsSection(
    @Param("id") scanSessionId: string,
    @Body() body: unknown,
    @Req() request: FastifyRequest
  ) {
    return this.scannerService.saveResultsSection(
      scanSessionId,
      parseBody(resultSectionSchema, body),
      request.ip
    );
  }

  @Post("sessions/:id/complete")
  completeSession(
    @Param("id") scanSessionId: string,
    @Body() body: unknown,
    @Req() request: FastifyRequest
  ) {
    return this.scannerService.completeSession(
      scanSessionId,
      parseBody(completeSchema, body),
      request.ip
    );
  }
}
