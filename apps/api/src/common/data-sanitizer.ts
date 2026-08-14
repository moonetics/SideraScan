import type { Prisma } from "@prisma/client";

const sensitiveKeyPatterns = [
  "rawkey",
  "scannerkey",
  "keyhash",
  "uploadtoken",
  "nonce",
  "noncehash",
  "machineguid",
  "serialnumber",
  "password",
  "token"
];

const windowsUserPathPattern = /([A-Za-z]:[\\/]+Users[\\/]+)([^\\/]+)([\\/]+)/gi;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function shouldRedactKey(key: string) {
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");

  return sensitiveKeyPatterns.some((pattern) => normalized.includes(pattern));
}

export function maskPrivatePath(value: string) {
  return value
    .split("\u0000")
    .join("")
    .replace(windowsUserPathPattern, "$1***$3");
}

export function sanitizeText(value: string) {
  return maskPrivatePath(value);
}

function sanitizeObjectKey(key: string) {
  const clean = key.split("\u0000").join("").trim();

  return clean || "field";
}

export function sanitizeForStorage(value: unknown): Prisma.InputJsonValue {
  if (value === undefined || value === null) {
    return {};
  }

  if (typeof value === "string") {
    return maskPrivatePath(value);
  }

  if (
    typeof value === "number" ||
    typeof value === "boolean" ||
    Array.isArray(value)
  ) {
    if (!Array.isArray(value)) {
      return value;
    }

    return value.map((item) => sanitizeForStorage(item));
  }

  if (!isPlainObject(value)) {
  const serialized =
    value instanceof Date ? value.toISOString() : JSON.stringify(value);

  return maskPrivatePath(serialized ?? "[UNSUPPORTED]");
}

  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      sanitizeObjectKey(key),
      shouldRedactKey(key) ? "[REDACTED]" : sanitizeForStorage(item)
    ])
  );
}

export function sanitizeJsonArray(value: unknown): Prisma.InputJsonValue {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.map((item) => sanitizeForStorage(item));
}
