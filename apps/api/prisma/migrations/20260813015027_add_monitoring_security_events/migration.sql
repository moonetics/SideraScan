-- CreateEnum
CREATE TYPE "MonitoringSeverity" AS ENUM ('INFO', 'WARNING', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "AlertNotificationStatus" AS ENUM ('PENDING', 'SENT', 'FAILED', 'DISABLED');

-- CreateTable
CREATE TABLE "monitoring_events" (
    "id" UUID NOT NULL,
    "service" VARCHAR(80) NOT NULL,
    "event_type" VARCHAR(120) NOT NULL,
    "severity" "MonitoringSeverity" NOT NULL DEFAULT 'INFO',
    "message" TEXT NOT NULL,
    "metadata" JSONB,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "monitoring_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_events" (
    "id" UUID NOT NULL,
    "account_id" UUID,
    "actor_user_id" UUID,
    "event_type" VARCHAR(120) NOT NULL,
    "severity" "MonitoringSeverity" NOT NULL,
    "source_ip" VARCHAR(64),
    "message" TEXT NOT NULL,
    "metadata" JSONB,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "security_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "alert_notifications" (
    "id" UUID NOT NULL,
    "security_event_id" UUID,
    "channel" VARCHAR(40) NOT NULL,
    "status" "AlertNotificationStatus" NOT NULL DEFAULT 'PENDING',
    "severity" "MonitoringSeverity" NOT NULL,
    "service" VARCHAR(80) NOT NULL,
    "event_type" VARCHAR(120) NOT NULL,
    "idempotency_key" VARCHAR(180) NOT NULL,
    "payload_redacted" JSONB NOT NULL,
    "attempt_count" INTEGER NOT NULL DEFAULT 0,
    "last_error" TEXT,
    "last_attempt_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "alert_notifications_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "monitoring_events_service_idx" ON "monitoring_events"("service");

-- CreateIndex
CREATE INDEX "monitoring_events_event_type_idx" ON "monitoring_events"("event_type");

-- CreateIndex
CREATE INDEX "monitoring_events_severity_idx" ON "monitoring_events"("severity");

-- CreateIndex
CREATE INDEX "monitoring_events_created_at_idx" ON "monitoring_events"("created_at");

-- CreateIndex
CREATE INDEX "security_events_account_id_idx" ON "security_events"("account_id");

-- CreateIndex
CREATE INDEX "security_events_actor_user_id_idx" ON "security_events"("actor_user_id");

-- CreateIndex
CREATE INDEX "security_events_event_type_idx" ON "security_events"("event_type");

-- CreateIndex
CREATE INDEX "security_events_severity_idx" ON "security_events"("severity");

-- CreateIndex
CREATE INDEX "security_events_source_ip_idx" ON "security_events"("source_ip");

-- CreateIndex
CREATE INDEX "security_events_created_at_idx" ON "security_events"("created_at");

-- CreateIndex
CREATE UNIQUE INDEX "alert_notifications_idempotency_key_key" ON "alert_notifications"("idempotency_key");

-- CreateIndex
CREATE INDEX "alert_notifications_security_event_id_idx" ON "alert_notifications"("security_event_id");

-- CreateIndex
CREATE INDEX "alert_notifications_channel_idx" ON "alert_notifications"("channel");

-- CreateIndex
CREATE INDEX "alert_notifications_status_idx" ON "alert_notifications"("status");

-- CreateIndex
CREATE INDEX "alert_notifications_severity_idx" ON "alert_notifications"("severity");

-- CreateIndex
CREATE INDEX "alert_notifications_event_type_idx" ON "alert_notifications"("event_type");

-- CreateIndex
CREATE INDEX "alert_notifications_created_at_idx" ON "alert_notifications"("created_at");

-- AddForeignKey
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_actor_user_id_fkey" FOREIGN KEY ("actor_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alert_notifications" ADD CONSTRAINT "alert_notifications_security_event_id_fkey" FOREIGN KEY ("security_event_id") REFERENCES "security_events"("id") ON DELETE CASCADE ON UPDATE CASCADE;
