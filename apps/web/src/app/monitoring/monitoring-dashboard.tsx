"use client";

import type { ColumnDef } from "@tanstack/react-table";
import {
  Activity,
  AlertTriangle,
  Bell,
  Bot,
  Database,
  RadioTower,
  ScanLine,
  ShieldAlert
} from "lucide-react";
import { useState } from "react";
import { DataTable } from "@/components/ui/data-table";
import {
  retryAlertNotification,
  type AlertNotification,
  type MonitoringOverview,
  type SecurityEvent
} from "@/lib/api";
import { formatJakartaDateTime } from "@/lib/date-format";
import { useConfirm } from "@/components/ui/confirm";
import { useToast } from "@/components/ui/toast";

type MonitoringDashboardProps = {
  alerts: AlertNotification[];
  overview: MonitoringOverview;
  securityEvents: SecurityEvent[];
};

const secretPattern =
  /(sds_live_[A-Za-z0-9-]+|sut_[A-Za-z0-9_-]+|snonce_[A-Za-z0-9_-]+)/g;
const privatePathPattern = /([A-Za-z]:[\\/]+Users[\\/]+)([^\\/]+)([\\/]+)/gi;

function maskText(value: string) {
  return value
    .replace(privatePathPattern, "$1***$3")
    .replace(secretPattern, "[REDACTED]");
}

function formatMetadata(value: unknown) {
  if (!value) {
    return "None";
  }

  return maskText(JSON.stringify(value));
}

function badgeClass(value: string) {
  if (["CRITICAL", "HIGH", "FAILED", "error"].includes(value)) {
    return "border-rose-300/30 bg-rose-400/10 text-rose-100";
  }

  if (["WARNING", "PENDING", "pending", "DISABLED"].includes(value)) {
    return "border-amber-300/30 bg-amber-400/10 text-amber-100";
  }

  return "border-emerald-300/30 bg-emerald-400/10 text-emerald-100";
}

function Badge({ value }: { value: string }) {
  return (
    <span
      className={`inline-flex w-fit rounded-md border px-2 py-1 text-xs font-semibold ${badgeClass(value)}`}
    >
      {value}
    </span>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  tone = "cyan"
}: {
  icon: typeof Activity;
  label: string;
  tone?: "amber" | "cyan" | "emerald" | "rose";
  value: string | number;
}) {
  const iconClass = {
    amber: "text-amber-200",
    cyan: "text-cyan-200",
    emerald: "text-emerald-200",
    rose: "text-rose-200"
  }[tone];

  return (
    <div className="rounded-lg border border-white/10 bg-[#172842] p-4">
      <div className="flex items-center gap-2 text-xs uppercase text-slate-400">
        <Icon className={`h-4 w-4 ${iconClass}`} />
        {label}
      </div>
      <p className="mt-3 text-2xl font-semibold text-slate-100">{value}</p>
    </div>
  );
}

export function MonitoringDashboard({
  alerts,
  overview,
  securityEvents
}: MonitoringDashboardProps) {
  const [retryMessage, setRetryMessage] = useState<string | null>(null);
  const confirm = useConfirm();
  const toast = useToast();
  const securityColumns: ColumnDef<SecurityEvent>[] = [
    {
      accessorKey: "severity",
      cell: ({ row }) => <Badge value={row.original.severity} />,
      header: "Severity"
    },
    {
      accessorKey: "eventType",
      header: "Event"
    },
    {
      accessorKey: "accountName",
      cell: ({ row }) => row.original.accountName ?? "Global",
      header: "Account"
    },
    {
      accessorKey: "message",
      cell: ({ row }) => (
        <span title={row.original.message}>{row.original.message}</span>
      ),
      header: "Message"
    },
    {
      accessorKey: "metadata",
      cell: ({ row }) => (
        <span
          className="line-clamp-2 max-w-[360px] text-xs text-slate-400"
          title={formatMetadata(row.original.metadata)}
        >
          {formatMetadata(row.original.metadata)}
        </span>
      ),
      header: "Metadata"
    },
    {
      accessorKey: "createdAt",
      cell: ({ row }) => formatJakartaDateTime(row.original.createdAt),
      header: "Created"
    }
  ];
  const alertColumns: ColumnDef<AlertNotification>[] = [
    {
      accessorKey: "status",
      cell: ({ row }) => <Badge value={row.original.status} />,
      header: "Status"
    },
    {
      accessorKey: "severity",
      cell: ({ row }) => <Badge value={row.original.severity} />,
      header: "Severity"
    },
    {
      accessorKey: "eventType",
      header: "Event"
    },
    {
      accessorKey: "channel",
      header: "Channel"
    },
    {
      accessorKey: "attemptCount",
      header: "Attempts"
    },
    {
      accessorKey: "lastError",
      cell: ({ row }) => row.original.lastError ?? "None",
      header: "Last Error"
    },
    {
      accessorKey: "createdAt",
      cell: ({ row }) => formatJakartaDateTime(row.original.createdAt),
      header: "Created"
    },
    {
      accessorKey: "id",
      cell: ({ row }) => (
        <button
          className="h-8 rounded-md border border-cyan-300/30 bg-cyan-400/10 px-2 text-xs font-semibold text-cyan-100 transition hover:bg-cyan-400/16"
          onClick={async () => {
            const ok = await confirm({
              confirmLabel: "Retry alert",
              description: "This will send the alert notification to the configured n8n alert webhook again.",
              title: "Retry alert notification?"
            });

            if (!ok) {
              return;
            }

            setRetryMessage("Retrying alert...");
            try {
              const result = await retryAlertNotification(row.original.id);
              setRetryMessage(
                `Alert retry completed with status ${result.status}.`
              );
              toast.success(`Alert retry completed with status ${result.status}.`);
            } catch {
              setRetryMessage("Could not retry alert.");
              toast.error("Could not retry alert.");
            }
          }}
          type="button"
        >
          Retry
        </button>
      ),
      enableSorting: false,
      header: "Actions"
    }
  ];

  return (
    <div>
      <div className="flex flex-col justify-between gap-4 border-b border-white/10 pb-6 md:flex-row md:items-center">
        <div>
          <p className="text-sm font-medium text-cyan-200">Phase 10</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-normal">
            Monitoring
          </h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">
            System health, scanner upload status, n8n/AI review state, security
            events, and alert delivery history.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Badge value={`API ${overview.health.api}`} />
          <Badge value={`DB ${overview.health.database}`} />
          <Badge value={`n8n ${overview.health.n8n}`} />
          <Badge value={`AI ${overview.health.ai}`} />
        </div>
      </div>

      <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={ScanLine}
          label="Uploads Today"
          value={overview.scannerUploads.uploadsToday}
        />
        <StatCard
          icon={AlertTriangle}
          label="Upload Error Rate"
          tone={overview.scannerUploads.uploadErrorRate > 0 ? "amber" : "emerald"}
          value={`${overview.scannerUploads.uploadErrorRate}%`}
        />
        <StatCard
          icon={Bot}
          label="Pending AI Reviews"
          tone={overview.aiReviews.pending > 0 ? "amber" : "emerald"}
          value={overview.aiReviews.pending}
        />
        <StatCard
          icon={ShieldAlert}
          label="Security Alerts Today"
          tone={overview.security.highOrCriticalToday > 0 ? "rose" : "emerald"}
          value={overview.security.highOrCriticalToday}
        />
        <StatCard
          icon={Activity}
          label="Completed Scans Today"
          value={overview.scans.completedToday}
        />
        <StatCard
          icon={Database}
          label="Failed Scans Today"
          tone={overview.scans.failedToday > 0 ? "rose" : "emerald"}
          value={overview.scans.failedToday}
        />
        <StatCard
          icon={RadioTower}
          label="n8n Failed Events"
          tone={overview.n8n.failedEvents > 0 ? "rose" : "emerald"}
          value={overview.n8n.failedEvents}
        />
        <StatCard
          icon={Bell}
          label="Failed Alerts"
          tone={overview.alerts.failed > 0 ? "rose" : "emerald"}
          value={overview.alerts.failed}
        />
      </div>

      <div className="mt-6 grid gap-4 xl:grid-cols-2">
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <h2 className="text-lg font-semibold text-slate-100">
            n8n Workflow Status
          </h2>
          {overview.n8n.latestEvent ? (
            <div className="mt-4 space-y-2 text-sm text-slate-300">
              <p>Latest event: {overview.n8n.latestEvent.eventType}</p>
              <p>
                Status: <Badge value={overview.n8n.latestEvent.status} />
              </p>
              <p>Attempts: {overview.n8n.latestEvent.attemptCount}</p>
              <p>
                Updated:{" "}
                {formatJakartaDateTime(overview.n8n.latestEvent.updatedAt)}
              </p>
              {overview.n8n.latestEvent.lastError ? (
                <p className="text-rose-100">
                  Error: {overview.n8n.latestEvent.lastError}
                </p>
              ) : null}
            </div>
          ) : (
            <p className="mt-4 text-sm text-slate-400">
              No n8n events have been recorded yet.
            </p>
          )}
        </section>

        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <h2 className="text-lg font-semibold text-slate-100">
            Scanner Uploads
          </h2>
          <div className="mt-4 grid gap-3 text-sm text-slate-300 sm:grid-cols-2">
            <div className="rounded-md border border-white/10 bg-slate-950/24 p-3">
              Failed uploads today:{" "}
              {overview.scannerUploads.failedUploadsToday}
            </div>
            <div className="rounded-md border border-white/10 bg-slate-950/24 p-3">
              Auth failures today:{" "}
              {overview.scannerUploads.uploadAuthFailuresToday}
            </div>
            <div className="rounded-md border border-white/10 bg-slate-950/24 p-3">
              Banned HWID matches today:{" "}
              {overview.security.bannedHwidMatchesToday}
            </div>
            <div className="rounded-md border border-white/10 bg-slate-950/24 p-3">
              Failed AI reviews: {overview.aiReviews.failed}
            </div>
          </div>
        </section>
      </div>

      <section className="mt-6 rounded-lg border border-white/10 bg-[#172842] p-4">
        <h2 className="text-lg font-semibold text-slate-100">
          Security Events
        </h2>
        <p className="mt-1 text-sm text-slate-400">
          Redacted event log for important scanner, n8n, HWID, and permission
          signals.
        </p>
        <div className="mt-4">
          <DataTable
            columns={securityColumns}
            data={securityEvents}
            emptyMessage="No security events recorded yet."
            pageSize={10}
            searchPlaceholder="Search security events..."
          />
        </div>
      </section>

      <section className="mt-6 rounded-lg border border-white/10 bg-[#172842] p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">
              Alert History
            </h2>
            <p className="mt-1 text-sm text-slate-400">
              n8n alert delivery attempts for high and critical events.
            </p>
          </div>
          {retryMessage ? (
            <span className="rounded-md border border-cyan-300/20 bg-cyan-400/10 px-3 py-2 text-xs font-semibold text-cyan-100">
              {retryMessage}
            </span>
          ) : null}
        </div>
        <div className="mt-4">
          <DataTable
            columns={alertColumns}
            data={alerts}
            emptyMessage="No alert notifications recorded yet."
            pageSize={10}
            searchPlaceholder="Search alert history..."
          />
        </div>
      </section>
    </div>
  );
}
