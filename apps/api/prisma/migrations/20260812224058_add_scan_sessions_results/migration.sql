-- CreateEnum
CREATE TYPE "ScanStatus" AS ENUM ('CREATED', 'KEY_VALIDATED', 'CONSENT_ACCEPTED', 'RUNNING', 'UPLOADING', 'COMPLETED', 'PARTIAL', 'FAILED', 'PENDING_AI_REVIEW', 'AI_REVIEWED', 'PENDING_MODERATOR', 'NEEDS_RESCAN', 'CLEARED', 'FLAGGED', 'ESCALATED');

-- CreateEnum
CREATE TYPE "ScanReviewStatus" AS ENUM ('UNREVIEWED', 'PENDING', 'REVIEWED', 'CLEARED', 'FLAGGED', 'ESCALATED');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('INFO', 'CLEAN', 'WARNING', 'SEVERE', 'CRITICAL');

-- CreateEnum
CREATE TYPE "FindingCategory" AS ENUM ('OVERVIEW', 'DEVICE', 'PROCESS', 'FILE', 'FILE_LOG', 'UTILITY', 'WINDOWS_ITEM', 'LAUNCHER_PROFILE', 'CLIENT_MOD_ASSET', 'CUSTOM_DETECTION', 'INTEGRITY', 'NETWORK', 'AI');

-- CreateTable
CREATE TABLE "scan_sessions" (
    "id" UUID NOT NULL,
    "account_id" UUID NOT NULL,
    "scanner_key_id" UUID NOT NULL,
    "device_id" UUID,
    "player_label" VARCHAR(160),
    "status" "ScanStatus" NOT NULL DEFAULT 'KEY_VALIDATED',
    "scanner_version" VARCHAR(40) NOT NULL,
    "platform" VARCHAR(40) NOT NULL,
    "arch" VARCHAR(40) NOT NULL,
    "upload_token_hash" TEXT NOT NULL,
    "nonce_hash" TEXT NOT NULL,
    "consent_accepted_at" TIMESTAMPTZ(3),
    "started_at" TIMESTAMPTZ(3),
    "finished_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "source_ip" VARCHAR(64),
    "ip_country" VARCHAR(80),
    "ip_region" VARCHAR(120),
    "risk_score" INTEGER NOT NULL DEFAULT 0,
    "max_severity" "Severity" NOT NULL DEFAULT 'CLEAN',
    "review_status" "ScanReviewStatus" NOT NULL DEFAULT 'UNREVIEWED',

    CONSTRAINT "scan_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_results" (
    "id" UUID NOT NULL,
    "scan_session_id" UUID NOT NULL,
    "account_id" UUID NOT NULL,
    "payload_hash" TEXT NOT NULL,
    "overview" JSONB NOT NULL,
    "system_identity" JSONB NOT NULL,
    "network_snapshot" JSONB NOT NULL,
    "integrity" JSONB NOT NULL,
    "raw_payload_ref" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_results_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_findings" (
    "id" UUID NOT NULL,
    "scan_session_id" UUID NOT NULL,
    "account_id" UUID NOT NULL,
    "rule_id" UUID,
    "category" "FindingCategory" NOT NULL,
    "severity" "Severity" NOT NULL,
    "title" VARCHAR(200) NOT NULL,
    "message" TEXT NOT NULL,
    "evidence_id" UUID,
    "confidence" INTEGER NOT NULL DEFAULT 100,
    "source_module" VARCHAR(80),
    "metadata" JSONB,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_findings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "scan_sessions_account_id_idx" ON "scan_sessions"("account_id");

-- CreateIndex
CREATE INDEX "scan_sessions_scanner_key_id_idx" ON "scan_sessions"("scanner_key_id");

-- CreateIndex
CREATE INDEX "scan_sessions_device_id_idx" ON "scan_sessions"("device_id");

-- CreateIndex
CREATE INDEX "scan_sessions_status_idx" ON "scan_sessions"("status");

-- CreateIndex
CREATE INDEX "scan_sessions_created_at_idx" ON "scan_sessions"("created_at");

-- CreateIndex
CREATE INDEX "scan_sessions_risk_score_idx" ON "scan_sessions"("risk_score");

-- CreateIndex
CREATE INDEX "scan_sessions_max_severity_idx" ON "scan_sessions"("max_severity");

-- CreateIndex
CREATE UNIQUE INDEX "scan_results_scan_session_id_key" ON "scan_results"("scan_session_id");

-- CreateIndex
CREATE INDEX "scan_results_account_id_idx" ON "scan_results"("account_id");

-- CreateIndex
CREATE INDEX "scan_results_payload_hash_idx" ON "scan_results"("payload_hash");

-- CreateIndex
CREATE INDEX "scan_findings_scan_session_id_idx" ON "scan_findings"("scan_session_id");

-- CreateIndex
CREATE INDEX "scan_findings_account_id_idx" ON "scan_findings"("account_id");

-- CreateIndex
CREATE INDEX "scan_findings_category_idx" ON "scan_findings"("category");

-- CreateIndex
CREATE INDEX "scan_findings_severity_idx" ON "scan_findings"("severity");

-- CreateIndex
CREATE INDEX "scan_findings_rule_id_idx" ON "scan_findings"("rule_id");

-- CreateIndex
CREATE INDEX "scan_findings_created_at_idx" ON "scan_findings"("created_at");

-- AddForeignKey
ALTER TABLE "scan_sessions" ADD CONSTRAINT "scan_sessions_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_sessions" ADD CONSTRAINT "scan_sessions_scanner_key_id_fkey" FOREIGN KEY ("scanner_key_id") REFERENCES "scanner_keys"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_scan_session_id_fkey" FOREIGN KEY ("scan_session_id") REFERENCES "scan_sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_findings" ADD CONSTRAINT "scan_findings_scan_session_id_fkey" FOREIGN KEY ("scan_session_id") REFERENCES "scan_sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_findings" ADD CONSTRAINT "scan_findings_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
