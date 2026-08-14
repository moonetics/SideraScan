import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z
    .enum(["development", "test", "production"])
    .default("development"),
  DATABASE_URL: z.string().url(),
  API_PORT: z.coerce.number().int().positive().default(4000),
  API_BODY_LIMIT_BYTES: z.coerce
    .number()
    .int()
    .positive()
    .default(31457280),
  WEB_ORIGIN: z.string().url().default("http://localhost:3000"),
  AUTH_SECRET: z.string().min(32),
  SESSION_COOKIE_NAME: z.string().min(1).default("siderascan_session"),
  SESSION_TTL_SECONDS: z.coerce.number().int().positive().default(28800),
  SEED_SUPER_ADMIN_EMAIL: z
    .string()
    .email()
    .default("admin@example.com"),
  SEED_SUPER_ADMIN_USERNAME: z.string().min(3).default("superadmin"),
  SEED_SUPER_ADMIN_PASSWORD: z.string().min(12).default("ChangeMe12345!"),
  SEED_SUPER_ADMIN_DISPLAY_NAME: z.string().min(1).default("Super Admin"),
  SCANNER_KEY_HASH_SECRET: z.string().min(32),
  SCANNER_UPLOAD_TOKEN_SECRET: z.string().min(32),
  SCANNER_UPLOAD_TOKEN_TTL_SECONDS: z.coerce
    .number()
    .int()
    .positive()
    .default(1800),
  N8N_SCAN_COMPLETED_WEBHOOK_URL: z.string().url().optional(),
  N8N_WEBHOOK_SECRET: z
    .string()
    .min(32)
    .default("dev-only-change-n8n-webhook-secret-32-chars"),
  N8N_WEBHOOK_ENABLED: z
    .enum(["true", "false"])
    .default("false")
    .transform((value) => value === "true"),
  N8N_MAX_ATTEMPTS: z.coerce.number().int().positive().default(3),
  N8N_SIGNATURE_TOLERANCE_SECONDS: z.coerce
    .number()
    .int()
    .positive()
    .default(300),
  N8N_ALERT_WEBHOOK_URL: z.string().url().optional(),
  N8N_ALERT_WEBHOOK_ENABLED: z
    .enum(["true", "false"])
    .default("false")
    .transform((value) => value === "true"),
  N8N_ALERT_MAX_ATTEMPTS: z.coerce.number().int().positive().default(3),
  REPORT_EXPORT_MAX_FINDINGS: z.coerce.number().int().positive().default(500),
  RETENTION_SCAN_RESULTS_DAYS: z.coerce.number().int().positive().default(90),
  RETENTION_FINDINGS_EVIDENCE_DAYS: z.coerce
    .number()
    .int()
    .positive()
    .default(90),
  RETENTION_SCREENSHOTS_DAYS: z.coerce.number().int().positive().default(30),
  RETENTION_DETECTION_SAMPLES_DAYS: z.coerce
    .number()
    .int()
    .positive()
    .default(7),
  RETENTION_MONITORING_EVENTS_DAYS: z.coerce
    .number()
    .int()
    .positive()
    .default(30),
  RETENTION_SECURITY_EVENTS_DAYS: z.coerce
    .number()
    .int()
    .positive()
    .default(180),
  RETENTION_AUDIT_LOGS_DAYS: z.coerce.number().int().positive().default(365),
  EXECUTOR_INTEL_ENABLED: z
    .enum(["true", "false"])
    .default("true")
    .transform((value) => value === "true"),
  EXECUTOR_INTEL_SOURCE_URL: z
    .string()
    .url()
    .default("https://executors.online/api/executors"),
  EXECUTOR_INTEL_FALLBACK_URL: z
    .string()
    .url()
    .default("https://weao.xyz/api/status/exploits"),
  EXECUTOR_INTEL_CACHE_TTL_SECONDS: z.coerce
    .number()
    .int()
    .positive()
    .default(86400),
  EXECUTOR_INTEL_AUTO_SYNC_ENABLED: z
    .enum(["true", "false"])
    .default("true")
    .transform((value) => value === "true"),
  EXECUTOR_INTEL_AUTO_SYNC_INTERVAL_SECONDS: z.coerce
    .number()
    .int()
    .positive()
    .default(86400),
  EXECUTOR_INTEL_SYNC_COOLDOWN_SECONDS: z.coerce
    .number()
    .int()
    .positive()
    .default(3600),
  APP_DASHBOARD_URL: z.string().url().default("http://localhost:3000")
});

export const env = envSchema.parse(process.env);
