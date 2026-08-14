import Link from "next/link";
import { Activity, AlertTriangle, Gauge, ScanSearch } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { getScans } from "@/lib/api";
import { formatJakartaDateTime } from "@/lib/date-format";
import { scanDisplayLabel } from "@/lib/scan-label";
import { getCookieHeader, requireCurrentUser } from "@/lib/session";

function statusClass(status: string) {
  if (status === "COMPLETED" || status === "CLEARED") {
    return "border-emerald-300/30 bg-emerald-400/10 text-emerald-100";
  }

  if (status === "FAILED" || status === "ESCALATED" || status === "FLAGGED") {
    return "border-rose-300/30 bg-rose-400/10 text-rose-100";
  }

  return "border-cyan-300/30 bg-cyan-400/10 text-cyan-100";
}

function severityClass(severity: string) {
  if (severity === "CRITICAL" || severity === "SEVERE") {
    return "border-rose-300/30 bg-rose-400/10 text-rose-100";
  }

  if (severity === "WARNING") {
    return "border-amber-300/30 bg-amber-400/10 text-amber-100";
  }

  return "border-emerald-300/30 bg-emerald-400/10 text-emerald-100";
}

function formatDate(value: string | null) {
  if (!value) {
    return "Not finished";
  }

  return formatJakartaDateTime(value);
}

export default async function ScansPage() {
  const cookieHeader = await getCookieHeader();
  const currentUser = await requireCurrentUser(cookieHeader);
  const scans = await getScans(cookieHeader);

  return (
    <AppShell currentUser={currentUser}>
      <div className="flex flex-col justify-between gap-4 border-b border-white/10 pb-6 md:flex-row md:items-center">
        <div>
          <p className="text-sm font-medium text-cyan-200">Phase 4</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-normal">
            Scans
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-300">
            Review scan sessions created from scanner key validation and dummy
            result uploads.
          </p>
        </div>

        <div className="flex gap-3">
          <div className="rounded-md border border-white/10 bg-white/5 px-3 py-2">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <ScanSearch className="h-4 w-4 text-cyan-200" />
              Visible scans
            </div>
            <p className="mt-1 text-lg font-semibold text-slate-100">
              {scans.length}
            </p>
          </div>
          <div className="rounded-md border border-white/10 bg-white/5 px-3 py-2">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <AlertTriangle className="h-4 w-4 text-amber-200" />
              Findings
            </div>
            <p className="mt-1 text-lg font-semibold text-slate-100">
              {scans.reduce((total, scan) => total + scan.findingCount, 0)}
            </p>
          </div>
        </div>
      </div>

      <div className="mt-6 overflow-hidden rounded-lg border border-white/10">
        <div className="grid grid-cols-[1fr_1fr_135px_120px_110px_170px] bg-slate-950/45 px-4 py-3 text-xs font-semibold uppercase text-slate-400">
          <span>Scan</span>
          <span>Account</span>
          <span>Status</span>
          <span>Severity</span>
          <span>Risk</span>
          <span>Finished</span>
        </div>

        {scans.length === 0 ? (
          <div className="flex items-center gap-3 px-4 py-8 text-sm text-slate-300">
            <Activity className="h-5 w-5 text-cyan-200" />
            No scan sessions available yet.
          </div>
        ) : (
          scans.map((scan) => (
            <Link
              className="grid grid-cols-[1fr_1fr_135px_120px_110px_170px] items-center border-t border-white/10 px-4 py-4 text-sm transition hover:bg-white/6"
              href={`/scans/${scan.id}`}
              key={scan.id}
            >
              <span className="min-w-0">
                <span className="block truncate font-medium text-slate-100">
                  {scanDisplayLabel(scan)}
                </span>
                <span className="mt-1 block truncate font-mono text-xs text-slate-400">
                  {scan.scannerKeyPrefix} - {scan.scannerVersion}
                </span>
              </span>
              <span className="truncate text-slate-300">{scan.accountName}</span>
              <span
                className={`w-fit rounded-md border px-2 py-1 text-xs font-semibold ${statusClass(scan.status)}`}
              >
                {scan.status}
              </span>
              <span
                className={`w-fit rounded-md border px-2 py-1 text-xs font-semibold ${severityClass(scan.maxSeverity)}`}
              >
                {scan.maxSeverity}
              </span>
              <span className="flex items-center gap-2 text-slate-300">
                <Gauge className="h-4 w-4 text-cyan-200" />
                {scan.riskScore}
              </span>
              <span className="text-xs text-slate-400">
                {formatDate(scan.finishedAt)}
              </span>
            </Link>
          ))
        )}
      </div>
    </AppShell>
  );
}
