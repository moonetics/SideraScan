-- CreateEnum
CREATE TYPE "DetectionRuleScope" AS ENUM ('GLOBAL', 'ACCOUNT');

-- CreateEnum
CREATE TYPE "DetectionRuleType" AS ENUM ('PROCESS_NAME', 'FILE_HASH', 'PATH_PATTERN', 'STRING_SIGNATURE');

-- CreateEnum
CREATE TYPE "DetectionSampleStatus" AS ENUM ('EXTRACTED', 'PURGED', 'FAILED');

-- CreateTable
CREATE TABLE "detection_rules" (
    "id" UUID NOT NULL,
    "account_id" UUID,
    "scope" "DetectionRuleScope" NOT NULL,
    "name" VARCHAR(160) NOT NULL,
    "type" "DetectionRuleType" NOT NULL,
    "category" "FindingCategory" NOT NULL DEFAULT 'CUSTOM_DETECTION',
    "severity" "Severity" NOT NULL DEFAULT 'WARNING',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "rule_config" JSONB NOT NULL,
    "hit_count" INTEGER NOT NULL DEFAULT 0,
    "created_by" UUID,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "deleted_at" TIMESTAMPTZ(3),

    CONSTRAINT "detection_rules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "detection_samples" (
    "id" UUID NOT NULL,
    "account_id" UUID,
    "uploaded_by" UUID,
    "file_name" VARCHAR(240) NOT NULL,
    "file_hash" TEXT NOT NULL,
    "storage_ref" VARCHAR(500),
    "size_bytes" INTEGER NOT NULL,
    "status" "DetectionSampleStatus" NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deleted_at" TIMESTAMPTZ(3),

    CONSTRAINT "detection_samples_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "detection_sample_strings" (
    "id" UUID NOT NULL,
    "sample_id" UUID NOT NULL,
    "value_hash" TEXT NOT NULL,
    "preview" VARCHAR(180) NOT NULL,
    "length" INTEGER NOT NULL,
    "selected_for_rule" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "detection_sample_strings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "detection_rules_account_id_idx" ON "detection_rules"("account_id");

-- CreateIndex
CREATE INDEX "detection_rules_scope_idx" ON "detection_rules"("scope");

-- CreateIndex
CREATE INDEX "detection_rules_type_idx" ON "detection_rules"("type");

-- CreateIndex
CREATE INDEX "detection_rules_category_idx" ON "detection_rules"("category");

-- CreateIndex
CREATE INDEX "detection_rules_enabled_idx" ON "detection_rules"("enabled");

-- CreateIndex
CREATE INDEX "detection_rules_deleted_at_idx" ON "detection_rules"("deleted_at");

-- CreateIndex
CREATE INDEX "detection_samples_account_id_idx" ON "detection_samples"("account_id");

-- CreateIndex
CREATE INDEX "detection_samples_file_hash_idx" ON "detection_samples"("file_hash");

-- CreateIndex
CREATE INDEX "detection_samples_status_idx" ON "detection_samples"("status");

-- CreateIndex
CREATE INDEX "detection_sample_strings_sample_id_idx" ON "detection_sample_strings"("sample_id");

-- CreateIndex
CREATE INDEX "detection_sample_strings_value_hash_idx" ON "detection_sample_strings"("value_hash");

-- AddForeignKey
ALTER TABLE "scan_findings" ADD CONSTRAINT "scan_findings_rule_id_fkey" FOREIGN KEY ("rule_id") REFERENCES "detection_rules"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "detection_rules" ADD CONSTRAINT "detection_rules_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "detection_rules" ADD CONSTRAINT "detection_rules_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "detection_samples" ADD CONSTRAINT "detection_samples_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "detection_samples" ADD CONSTRAINT "detection_samples_uploaded_by_fkey" FOREIGN KEY ("uploaded_by") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "detection_sample_strings" ADD CONSTRAINT "detection_sample_strings_sample_id_fkey" FOREIGN KEY ("sample_id") REFERENCES "detection_samples"("id") ON DELETE CASCADE ON UPDATE CASCADE;
