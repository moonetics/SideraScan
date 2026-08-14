-- CreateEnum
CREATE TYPE "AiRecommendedAction" AS ENUM ('NO_ACTION', 'MONITOR', 'REQUEST_RESCAN', 'MANUAL_REVIEW', 'ESCALATE');

-- CreateEnum
CREATE TYPE "AutomationEventStatus" AS ENUM ('PENDING', 'SENT', 'FAILED', 'DISABLED');

-- AlterEnum
ALTER TYPE "ScanReviewStatus" ADD VALUE 'FAILED';

-- CreateTable
CREATE TABLE "ai_reviews" (
    "id" UUID NOT NULL,
    "scan_session_id" UUID NOT NULL,
    "account_id" UUID NOT NULL,
    "assessment" VARCHAR(80) NOT NULL,
    "confidence" INTEGER NOT NULL,
    "summary_for_moderator" TEXT NOT NULL,
    "summary_for_player" TEXT,
    "recommended_action" "AiRecommendedAction" NOT NULL,
    "key_indicators" JSONB NOT NULL DEFAULT '[]',
    "possible_false_positives" JSONB NOT NULL DEFAULT '[]',
    "contradictions" JSONB NOT NULL DEFAULT '[]',
    "moderator_checklist" JSONB NOT NULL DEFAULT '[]',
    "questions_for_player" JSONB NOT NULL DEFAULT '[]',
    "evidence_references" JSONB NOT NULL DEFAULT '[]',
    "model" VARCHAR(120),
    "prompt_version" VARCHAR(80),
    "input_hash" VARCHAR(128),
    "generated_at" TIMESTAMPTZ(3) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "ai_reviews_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ai_review_evidence" (
    "id" UUID NOT NULL,
    "ai_review_id" UUID NOT NULL,
    "scan_session_id" UUID NOT NULL,
    "finding_id" UUID,
    "evidence_id" UUID,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ai_review_evidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "automation_events" (
    "id" UUID NOT NULL,
    "event_type" VARCHAR(80) NOT NULL,
    "idempotency_key" VARCHAR(160) NOT NULL,
    "scan_session_id" UUID,
    "account_id" UUID,
    "status" "AutomationEventStatus" NOT NULL DEFAULT 'PENDING',
    "payload" JSONB NOT NULL,
    "attempt_count" INTEGER NOT NULL DEFAULT 0,
    "last_error" TEXT,
    "last_attempt_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "automation_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ai_reviews_scan_session_id_key" ON "ai_reviews"("scan_session_id");

-- CreateIndex
CREATE INDEX "ai_reviews_account_id_idx" ON "ai_reviews"("account_id");

-- CreateIndex
CREATE INDEX "ai_reviews_assessment_idx" ON "ai_reviews"("assessment");

-- CreateIndex
CREATE INDEX "ai_reviews_recommended_action_idx" ON "ai_reviews"("recommended_action");

-- CreateIndex
CREATE INDEX "ai_reviews_generated_at_idx" ON "ai_reviews"("generated_at");

-- CreateIndex
CREATE INDEX "ai_review_evidence_ai_review_id_idx" ON "ai_review_evidence"("ai_review_id");

-- CreateIndex
CREATE INDEX "ai_review_evidence_scan_session_id_idx" ON "ai_review_evidence"("scan_session_id");

-- CreateIndex
CREATE INDEX "ai_review_evidence_finding_id_idx" ON "ai_review_evidence"("finding_id");

-- CreateIndex
CREATE INDEX "ai_review_evidence_evidence_id_idx" ON "ai_review_evidence"("evidence_id");

-- CreateIndex
CREATE UNIQUE INDEX "automation_events_idempotency_key_key" ON "automation_events"("idempotency_key");

-- CreateIndex
CREATE INDEX "automation_events_event_type_idx" ON "automation_events"("event_type");

-- CreateIndex
CREATE INDEX "automation_events_scan_session_id_idx" ON "automation_events"("scan_session_id");

-- CreateIndex
CREATE INDEX "automation_events_account_id_idx" ON "automation_events"("account_id");

-- CreateIndex
CREATE INDEX "automation_events_status_idx" ON "automation_events"("status");

-- CreateIndex
CREATE INDEX "automation_events_updated_at_idx" ON "automation_events"("updated_at");

-- AddForeignKey
ALTER TABLE "ai_reviews" ADD CONSTRAINT "ai_reviews_scan_session_id_fkey" FOREIGN KEY ("scan_session_id") REFERENCES "scan_sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_reviews" ADD CONSTRAINT "ai_reviews_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_review_evidence" ADD CONSTRAINT "ai_review_evidence_ai_review_id_fkey" FOREIGN KEY ("ai_review_id") REFERENCES "ai_reviews"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_review_evidence" ADD CONSTRAINT "ai_review_evidence_scan_session_id_fkey" FOREIGN KEY ("scan_session_id") REFERENCES "scan_sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_review_evidence" ADD CONSTRAINT "ai_review_evidence_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "scan_findings"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_review_evidence" ADD CONSTRAINT "ai_review_evidence_evidence_id_fkey" FOREIGN KEY ("evidence_id") REFERENCES "scan_evidence"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "automation_events" ADD CONSTRAINT "automation_events_scan_session_id_fkey" FOREIGN KEY ("scan_session_id") REFERENCES "scan_sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "automation_events" ADD CONSTRAINT "automation_events_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
