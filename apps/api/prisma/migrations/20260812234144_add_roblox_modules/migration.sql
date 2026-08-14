-- CreateTable
CREATE TABLE "launcher_profiles" (
    "id" UUID NOT NULL,
    "scan_session_id" UUID NOT NULL,
    "account_id" UUID NOT NULL,
    "profile_name" VARCHAR(160) NOT NULL,
    "launcher_type" VARCHAR(80) NOT NULL,
    "version" VARCHAR(80),
    "channel" VARCHAR(80),
    "path_masked" VARCHAR(500),
    "executable_hash" VARCHAR(128),
    "publisher" VARCHAR(160),
    "status" VARCHAR(40) NOT NULL DEFAULT 'normal',
    "tags" JSONB NOT NULL DEFAULT '[]',
    "install_time" TIMESTAMPTZ(3),
    "update_time" TIMESTAMPTZ(3),
    "last_launch_time" TIMESTAMPTZ(3),
    "metadata" JSONB,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "launcher_profiles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "client_mod_assets" (
    "id" UUID NOT NULL,
    "scan_session_id" UUID NOT NULL,
    "account_id" UUID NOT NULL,
    "name" VARCHAR(160) NOT NULL,
    "source_launcher" VARCHAR(160),
    "path_masked" VARCHAR(500),
    "file_count" INTEGER,
    "total_size" BIGINT,
    "created_time" TIMESTAMPTZ(3),
    "modified_time" TIMESTAMPTZ(3),
    "status" VARCHAR(40) NOT NULL DEFAULT 'normal',
    "metadata" JSONB,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "client_mod_assets_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "process_times" (
    "id" UUID NOT NULL,
    "scan_session_id" UUID NOT NULL,
    "account_id" UUID NOT NULL,
    "process_name" VARCHAR(160) NOT NULL,
    "path_masked" VARCHAR(500),
    "first_seen_at" TIMESTAMPTZ(3),
    "last_seen_at" TIMESTAMPTZ(3),
    "started_at" TIMESTAMPTZ(3),
    "ended_at" TIMESTAMPTZ(3),
    "duration_ms" INTEGER,
    "source" VARCHAR(80),
    "status" VARCHAR(40) NOT NULL DEFAULT 'normal',
    "metadata" JSONB,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "process_times_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "file_logs" (
    "id" UUID NOT NULL,
    "scan_session_id" UUID NOT NULL,
    "account_id" UUID NOT NULL,
    "action" VARCHAR(80) NOT NULL,
    "path_masked" VARCHAR(500),
    "old_path_masked" VARCHAR(500),
    "new_path_masked" VARCHAR(500),
    "timestamp" TIMESTAMPTZ(3),
    "source" VARCHAR(120),
    "confidence" INTEGER,
    "related_process" VARCHAR(160),
    "severity" "Severity" NOT NULL DEFAULT 'INFO',
    "metadata" JSONB,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "file_logs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "launcher_profiles_scan_session_id_idx" ON "launcher_profiles"("scan_session_id");

-- CreateIndex
CREATE INDEX "launcher_profiles_account_id_idx" ON "launcher_profiles"("account_id");

-- CreateIndex
CREATE INDEX "launcher_profiles_launcher_type_idx" ON "launcher_profiles"("launcher_type");

-- CreateIndex
CREATE INDEX "launcher_profiles_executable_hash_idx" ON "launcher_profiles"("executable_hash");

-- CreateIndex
CREATE INDEX "launcher_profiles_status_idx" ON "launcher_profiles"("status");

-- CreateIndex
CREATE INDEX "client_mod_assets_scan_session_id_idx" ON "client_mod_assets"("scan_session_id");

-- CreateIndex
CREATE INDEX "client_mod_assets_account_id_idx" ON "client_mod_assets"("account_id");

-- CreateIndex
CREATE INDEX "client_mod_assets_source_launcher_idx" ON "client_mod_assets"("source_launcher");

-- CreateIndex
CREATE INDEX "client_mod_assets_status_idx" ON "client_mod_assets"("status");

-- CreateIndex
CREATE INDEX "client_mod_assets_modified_time_idx" ON "client_mod_assets"("modified_time");

-- CreateIndex
CREATE INDEX "process_times_scan_session_id_idx" ON "process_times"("scan_session_id");

-- CreateIndex
CREATE INDEX "process_times_account_id_idx" ON "process_times"("account_id");

-- CreateIndex
CREATE INDEX "process_times_process_name_idx" ON "process_times"("process_name");

-- CreateIndex
CREATE INDEX "process_times_started_at_idx" ON "process_times"("started_at");

-- CreateIndex
CREATE INDEX "process_times_status_idx" ON "process_times"("status");

-- CreateIndex
CREATE INDEX "file_logs_scan_session_id_idx" ON "file_logs"("scan_session_id");

-- CreateIndex
CREATE INDEX "file_logs_account_id_idx" ON "file_logs"("account_id");

-- CreateIndex
CREATE INDEX "file_logs_action_idx" ON "file_logs"("action");

-- CreateIndex
CREATE INDEX "file_logs_timestamp_idx" ON "file_logs"("timestamp");

-- CreateIndex
CREATE INDEX "file_logs_severity_idx" ON "file_logs"("severity");

-- CreateIndex
CREATE INDEX "file_logs_related_process_idx" ON "file_logs"("related_process");

-- AddForeignKey
ALTER TABLE "launcher_profiles" ADD CONSTRAINT "launcher_profiles_scan_session_id_fkey" FOREIGN KEY ("scan_session_id") REFERENCES "scan_sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "launcher_profiles" ADD CONSTRAINT "launcher_profiles_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "client_mod_assets" ADD CONSTRAINT "client_mod_assets_scan_session_id_fkey" FOREIGN KEY ("scan_session_id") REFERENCES "scan_sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "client_mod_assets" ADD CONSTRAINT "client_mod_assets_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "process_times" ADD CONSTRAINT "process_times_scan_session_id_fkey" FOREIGN KEY ("scan_session_id") REFERENCES "scan_sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "process_times" ADD CONSTRAINT "process_times_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "file_logs" ADD CONSTRAINT "file_logs_scan_session_id_fkey" FOREIGN KEY ("scan_session_id") REFERENCES "scan_sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "file_logs" ADD CONSTRAINT "file_logs_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
