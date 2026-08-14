-- AlterTable
ALTER TABLE "scan_results" ADD COLUMN     "defender_events" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "dns_cache" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "drivers" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "event_logs" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "execution_artifacts" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "file_triage" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "forensic_timeline" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "hosts_entries" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "loaded_modules" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "network_connections" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "persistence_items" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "process_handles" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "services" JSONB NOT NULL DEFAULT '[]';
