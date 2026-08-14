import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { env } from "../config/env";

function createSecret(prefix: string): string {
  return `${prefix}_${randomBytes(32).toString("base64url")}`;
}

export function createUploadToken(): string {
  return createSecret("sut");
}

export function createNonce(): string {
  return createSecret("snonce");
}

export function hashUploadSecret(value: string): string {
  return createHmac("sha256", env.SCANNER_UPLOAD_TOKEN_SECRET)
    .update(value, "utf8")
    .digest("hex");
}

export function safeHashEquals(inputValue: string, expectedHash: string): boolean {
  const inputHash = hashUploadSecret(inputValue);
  const input = Buffer.from(inputHash, "hex");
  const expected = Buffer.from(expectedHash, "hex");

  return input.length === expected.length && timingSafeEqual(input, expected);
}

