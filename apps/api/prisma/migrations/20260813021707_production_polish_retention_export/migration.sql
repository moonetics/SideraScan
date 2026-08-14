-- CreateTable
CREATE TABLE "retention_settings" (
    "id" VARCHAR(40) NOT NULL DEFAULT 'global',
    "scan_results_days" INTEGER NOT NULL DEFAULT 90,
    "findings_evidence_days" INTEGER NOT NULL DEFAULT 90,
    "screenshots_days" INTEGER NOT NULL DEFAULT 30,
    "detection_samples_days" INTEGER NOT NULL DEFAULT 7,
    "monitoring_events_days" INTEGER NOT NULL DEFAULT 30,
    "security_events_days" INTEGER NOT NULL DEFAULT 180,
    "audit_logs_days" INTEGER NOT NULL DEFAULT 365,
    "updated_by" UUID,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "retention_settings_pkey" PRIMARY KEY ("id")
);
