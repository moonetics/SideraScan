import { timingSafeEqual, createHmac } from "node:crypto";
import { UnauthorizedException } from "@nestjs/common";
import type { FastifyRequest } from "fastify";
import { env } from "../config/env";

const signaturePrefix = "sha256=";

export function bodyToSignedString(body: unknown) {
  return JSON.stringify(body ?? {});
}

export function signN8nPayload(timestamp: string, body: string) {
  return `${signaturePrefix}${createHmac("sha256", env.N8N_WEBHOOK_SECRET)
    .update(`${timestamp}.${body}`)
    .digest("hex")}`;
}

function singleHeader(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

export function assertValidN8nSignature(
  request: FastifyRequest,
  body: unknown
) {
  const timestamp = singleHeader(request.headers["x-siderascan-timestamp"]);
  const signature = singleHeader(request.headers["x-siderascan-signature"]);

  if (!timestamp || !signature) {
    throw new UnauthorizedException("Missing n8n signature");
  }

  const unixSeconds = Number(timestamp);

  if (!Number.isFinite(unixSeconds)) {
    throw new UnauthorizedException("Invalid n8n timestamp");
  }

  const ageSeconds = Math.abs(Date.now() / 1000 - unixSeconds);

  if (ageSeconds > env.N8N_SIGNATURE_TOLERANCE_SECONDS) {
    throw new UnauthorizedException("Expired n8n signature");
  }

  const expected = signN8nPayload(timestamp, bodyToSignedString(body));
  const provided = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);

  if (
    provided.length !== expectedBuffer.length ||
    !timingSafeEqual(provided, expectedBuffer)
  ) {
    throw new UnauthorizedException("Invalid n8n signature");
  }
}
