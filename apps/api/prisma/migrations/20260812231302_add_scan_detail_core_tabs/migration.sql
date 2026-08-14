-- AlterTable
ALTER TABLE "scan_results" ADD COLUMN     "audit_log" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "explore_files" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "process_timeline" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "utilities" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "windows_items" JSONB NOT NULL DEFAULT '[]';

-- CreateTable
CREATE TABLE "scan_modules" (
    "id" UUID NOT NULL,
    "scan_session_id" UUID NOT NULL,
    "account_id" UUID NOT NULL,
    "module_name" VARCHAR(80) NOT NULL,
    "status" VARCHAR(24) NOT NULL,
    "duration_ms" INTEGER,
    "error_code" VARCHAR(80),
    "error_message" VARCHAR(500),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_modules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_evidence" (
    "id" UUID NOT NULL,
    "scan_session_id" UUID NOT NULL,
    "account_id" UUID NOT NULL,
    "client_evidence_id" VARCHAR(120),
    "type" VARCHAR(80) NOT NULL,
    "title" VARCHAR(200) NOT NULL,
    "data" JSONB NOT NULL,
    "storage_ref" VARCHAR(500),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_evidence_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "scan_modules_scan_session_id_idx" ON "scan_modules"("scan_session_id");

-- CreateIndex
CREATE INDEX "scan_modules_account_id_idx" ON "scan_modules"("account_id");

-- CreateIndex
CREATE INDEX "scan_modules_module_name_idx" ON "scan_modules"("module_name");

-- CreateIndex
CREATE INDEX "scan_modules_status_idx" ON "scan_modules"("status");

-- CreateIndex
CREATE INDEX "scan_evidence_scan_session_id_idx" ON "scan_evidence"("scan_session_id");

-- CreateIndex
CREATE INDEX "scan_evidence_account_id_idx" ON "scan_evidence"("account_id");

-- CreateIndex
CREATE INDEX "scan_evidence_type_idx" ON "scan_evidence"("type");

-- CreateIndex
CREATE INDEX "scan_evidence_client_evidence_id_idx" ON "scan_evidence"("client_evidence_id");

-- AddForeignKey
ALTER TABLE "scan_findings" ADD CONSTRAINT "scan_findings_evidence_id_fkey" FOREIGN KEY ("evidence_id") REFERENCES "scan_evidence"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_modules" ADD CONSTRAINT "scan_modules_scan_session_id_fkey" FOREIGN KEY ("scan_session_id") REFERENCES "scan_sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_modules" ADD CONSTRAINT "scan_modules_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_evidence" ADD CONSTRAINT "scan_evidence_scan_session_id_fkey" FOREIGN KEY ("scan_session_id") REFERENCES "scan_sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_evidence" ADD CONSTRAINT "scan_evidence_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
