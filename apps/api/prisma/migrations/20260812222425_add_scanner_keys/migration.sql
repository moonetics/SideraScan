-- CreateEnum
CREATE TYPE "ScannerKeyStatus" AS ENUM ('ACTIVE', 'REVOKED', 'EXPIRED');

-- CreateTable
CREATE TABLE "scanner_keys" (
    "id" UUID NOT NULL,
    "account_id" UUID NOT NULL,
    "name" VARCHAR(120) NOT NULL,
    "key_prefix" VARCHAR(32) NOT NULL,
    "key_hash" TEXT NOT NULL,
    "status" "ScannerKeyStatus" NOT NULL DEFAULT 'ACTIVE',
    "created_by" UUID,
    "revoked_by" UUID,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "last_used_at" TIMESTAMPTZ(3),
    "usage_count" INTEGER NOT NULL DEFAULT 0,
    "expires_at" TIMESTAMPTZ(3),
    "revoked_at" TIMESTAMPTZ(3),
    "rate_limit_per_hour" INTEGER NOT NULL DEFAULT 60,
    "allowed_scanner_versions" JSONB,

    CONSTRAINT "scanner_keys_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "scanner_keys_key_hash_key" ON "scanner_keys"("key_hash");

-- CreateIndex
CREATE INDEX "scanner_keys_account_id_idx" ON "scanner_keys"("account_id");

-- CreateIndex
CREATE INDEX "scanner_keys_key_prefix_idx" ON "scanner_keys"("key_prefix");

-- CreateIndex
CREATE INDEX "scanner_keys_status_idx" ON "scanner_keys"("status");

-- AddForeignKey
ALTER TABLE "scanner_keys" ADD CONSTRAINT "scanner_keys_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scanner_keys" ADD CONSTRAINT "scanner_keys_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scanner_keys" ADD CONSTRAINT "scanner_keys_revoked_by_fkey" FOREIGN KEY ("revoked_by") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
