-- AlterTable
ALTER TABLE "detection_rules"
ADD COLUMN     "managed_by" VARCHAR(80),
ADD COLUMN     "managed_ref_id" VARCHAR(160);

-- CreateTable
CREATE TABLE "executor_intelligence_settings" (
    "id" VARCHAR(40) NOT NULL DEFAULT 'global',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "source_url" VARCHAR(500) NOT NULL DEFAULT 'https://executors.online/api/executors',
    "fallback_url" VARCHAR(500) NOT NULL DEFAULT 'https://weao.xyz/api/status/exploits',
    "cache_ttl_seconds" INTEGER NOT NULL DEFAULT 86400,
    "attribution" VARCHAR(200) NOT NULL DEFAULT 'Executors.Online / WhatExpsAre.Online',
    "last_sync_at" TIMESTAMPTZ(3),
    "last_success_at" TIMESTAMPTZ(3),
    "last_error" VARCHAR(500),
    "item_count" INTEGER NOT NULL DEFAULT 0,
    "windows_item_count" INTEGER NOT NULL DEFAULT 0,
    "generated_rule_count" INTEGER NOT NULL DEFAULT 0,
    "updated_by" UUID,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "executor_intelligence_settings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "executor_intelligence_items" (
    "id" UUID NOT NULL,
    "title" VARCHAR(160) NOT NULL,
    "slug" VARCHAR(180) NOT NULL,
    "platform" VARCHAR(80) NOT NULL,
    "extype" VARCHAR(80),
    "detected" BOOLEAN NOT NULL DEFAULT false,
    "update_status" BOOLEAN NOT NULL DEFAULT false,
    "version" VARCHAR(120),
    "updated_date_text" VARCHAR(160),
    "website_host" VARCHAR(160),
    "source_name" VARCHAR(120) NOT NULL,
    "source_url" VARCHAR(500) NOT NULL,
    "source_metadata" JSONB NOT NULL DEFAULT '{}',
    "generated_rule_ids" JSONB NOT NULL DEFAULT '[]',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "last_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "executor_intelligence_items_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "detection_rules_managed_by_idx" ON "detection_rules"("managed_by");

-- CreateIndex
CREATE INDEX "detection_rules_managed_ref_id_idx" ON "detection_rules"("managed_ref_id");

-- CreateIndex
CREATE UNIQUE INDEX "detection_rules_managed_by_managed_ref_id_type_key" ON "detection_rules"("managed_by", "managed_ref_id", "type");

-- CreateIndex
CREATE UNIQUE INDEX "executor_intelligence_items_source_name_slug_key" ON "executor_intelligence_items"("source_name", "slug");

-- CreateIndex
CREATE INDEX "executor_intelligence_items_platform_idx" ON "executor_intelligence_items"("platform");

-- CreateIndex
CREATE INDEX "executor_intelligence_items_extype_idx" ON "executor_intelligence_items"("extype");

-- CreateIndex
CREATE INDEX "executor_intelligence_items_enabled_idx" ON "executor_intelligence_items"("enabled");

-- CreateIndex
CREATE INDEX "executor_intelligence_items_detected_idx" ON "executor_intelligence_items"("detected");

-- CreateIndex
CREATE INDEX "executor_intelligence_items_update_status_idx" ON "executor_intelligence_items"("update_status");

-- CreateIndex
CREATE INDEX "executor_intelligence_items_last_seen_at_idx" ON "executor_intelligence_items"("last_seen_at");

-- AddForeignKey
ALTER TABLE "executor_intelligence_settings" ADD CONSTRAINT "executor_intelligence_settings_updated_by_fkey" FOREIGN KEY ("updated_by") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
