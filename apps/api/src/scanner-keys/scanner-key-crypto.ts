import { createHmac, randomBytes } from "node:crypto";
import { env } from "../config/env";

const KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const KEY_GROUPS = 5;
const KEY_GROUP_LENGTH = 4;

function randomKeyGroup(): string {
  const bytes = randomBytes(KEY_GROUP_LENGTH);
  let value = "";

  for (const byte of bytes) {
    value += KEY_ALPHABET[byte % KEY_ALPHABET.length];
  }

  return value;
}

export function generateRawScannerKey(): string {
  const groups = Array.from({ length: KEY_GROUPS }, randomKeyGroup);
  return `sds_live_${groups.join("-")}`;
}

export function getScannerKeyPrefix(rawKey: string): string {
  return rawKey.slice(0, 13);
}

export function hashScannerKey(rawKey: string): string {
  return createHmac("sha256", env.SCANNER_KEY_HASH_SECRET)
    .update(rawKey, "utf8")
    .digest("hex");
}
