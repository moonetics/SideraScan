-- CreateEnum
CREATE TYPE "DeviceMarkStatus" AS ENUM ('BANNED', 'SUSPICIOUS', 'TRUSTED', 'CLEARED');

-- CreateEnum
CREATE TYPE "DeviceMarkScope" AS ENUM ('GLOBAL', 'ACCOUNT');

-- CreateEnum
CREATE TYPE "FingerprintConfidence" AS ENUM ('LOW', 'MEDIUM', 'HIGH');

-- CreateTable
CREATE TABLE "devices" (
    "id" UUID NOT NULL,
    "fingerprint_hash" TEXT NOT NULL,
    "fingerprint_prefix" VARCHAR(24) NOT NULL,
    "fingerprint_version" VARCHAR(40) NOT NULL,
    "fingerprint_confidence" "FingerprintConfidence" NOT NULL DEFAULT 'MEDIUM',
    "first_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "scan_count" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "devices_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_account_links" (
    "id" UUID NOT NULL,
    "device_id" UUID NOT NULL,
    "account_id" UUID NOT NULL,
    "first_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "scan_count" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "device_account_links_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_marks" (
    "id" UUID NOT NULL,
    "device_id" UUID NOT NULL,
    "scope" "DeviceMarkScope" NOT NULL,
    "account_id" UUID,
    "status" "DeviceMarkStatus" NOT NULL,
    "reason" TEXT NOT NULL,
    "severity" "Severity" NOT NULL DEFAULT 'WARNING',
    "marked_by" UUID,
    "marked_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(3),
    "revoked_at" TIMESTAMPTZ(3),
    "revoked_by" UUID,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "device_marks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_mark_evidence" (
    "id" UUID NOT NULL,
    "device_mark_id" UUID NOT NULL,
    "scan_session_id" UUID,
    "finding_id" UUID,
    "note" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "device_mark_evidence_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "devices_fingerprint_hash_key" ON "devices"("fingerprint_hash");

-- CreateIndex
CREATE INDEX "devices_fingerprint_prefix_idx" ON "devices"("fingerprint_prefix");

-- CreateIndex
CREATE INDEX "devices_last_seen_at_idx" ON "devices"("last_seen_at");

-- CreateIndex
CREATE INDEX "device_account_links_account_id_idx" ON "device_account_links"("account_id");

-- CreateIndex
CREATE UNIQUE INDEX "device_account_links_device_id_account_id_key" ON "device_account_links"("device_id", "account_id");

-- CreateIndex
CREATE INDEX "device_marks_device_id_idx" ON "device_marks"("device_id");

-- CreateIndex
CREATE INDEX "device_marks_account_id_idx" ON "device_marks"("account_id");

-- CreateIndex
CREATE INDEX "device_marks_scope_idx" ON "device_marks"("scope");

-- CreateIndex
CREATE INDEX "device_marks_status_idx" ON "device_marks"("status");

-- CreateIndex
CREATE INDEX "device_marks_expires_at_idx" ON "device_marks"("expires_at");

-- CreateIndex
CREATE INDEX "device_mark_evidence_device_mark_id_idx" ON "device_mark_evidence"("device_mark_id");

-- CreateIndex
CREATE INDEX "device_mark_evidence_scan_session_id_idx" ON "device_mark_evidence"("scan_session_id");

-- AddForeignKey
ALTER TABLE "scan_sessions" ADD CONSTRAINT "scan_sessions_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_account_links" ADD CONSTRAINT "device_account_links_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_account_links" ADD CONSTRAINT "device_account_links_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_marks" ADD CONSTRAINT "device_marks_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_marks" ADD CONSTRAINT "device_marks_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_marks" ADD CONSTRAINT "device_marks_marked_by_fkey" FOREIGN KEY ("marked_by") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_marks" ADD CONSTRAINT "device_marks_revoked_by_fkey" FOREIGN KEY ("revoked_by") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_mark_evidence" ADD CONSTRAINT "device_mark_evidence_device_mark_id_fkey" FOREIGN KEY ("device_mark_id") REFERENCES "device_marks"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_mark_evidence" ADD CONSTRAINT "device_mark_evidence_scan_session_id_fkey" FOREIGN KEY ("scan_session_id") REFERENCES "scan_sessions"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_mark_evidence" ADD CONSTRAINT "device_mark_evidence_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "scan_findings"("id") ON DELETE SET NULL ON UPDATE CASCADE;
