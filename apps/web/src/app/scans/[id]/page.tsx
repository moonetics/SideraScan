import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, Clock, Gauge, ListChecks } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { getAccounts, getScan } from "@/lib/api";
import { formatJakartaDateTime } from "@/lib/date-format";
import { getCookieHeader, requireCurrentUser } from "@/lib/session";
import { scanDisplayLabel } from "@/lib/scan-label";
import { ScanDetailTabs } from "./scan-detail-tabs";
import { ScanLabelEditor } from "./scan-label-editor";
import { ReportExportLinks } from "./report-export-links";

type ScanDetailPageProps = {
  params: Promise<{
    id: string;
  }>;
};

function badgeClass(value: string) {
  if (["CRITICAL", "SEVERE", "FAILED", "FLAGGED"].includes(value)) {
    return "border-rose-300/30 bg-rose-400/10 text-rose-100";
  }

  if (["WARNING", "PARTIAL"].includes(value)) {
    return "border-amber-300/30 bg-amber-400/10 text-amber-100";
  }

  return "border-emerald-300/30 bg-emerald-400/10 text-emerald-100";
}

export default async function ScanDetailPage({ params }: ScanDetailPageProps) {
  const { id } = await params;
  const cookieHeader = await getCookieHeader();
  const currentUser = await requireCurrentUser(cookieHeader);
  let scan;

  try {
    scan = await getScan(id, cookieHeader);
  } catch {
    notFound();
  }

  let canRetryAiReview = currentUser.globalRole === "SUPER_ADMIN";
  let canExportReport = currentUser.globalRole === "SUPER_ADMIN";
  let canEditScanLabel = currentUser.globalRole === "SUPER_ADMIN";

  if (!canRetryAiReview || !canExportReport || !canEditScanLabel) {
    try {
      const accounts = await getAccounts(cookieHeader);
      const role = accounts.find(
        (account) => account.id === scan.accountId
      )?.viewerRole;

      canRetryAiReview = role === "ACCOUNT_OWNER";
      canExportReport = role === "ACCOUNT_OWNER" || role === "MODERATOR";
      canEditScanLabel = role === "ACCOUNT_OWNER" || role === "MODERATOR";
    } catch {
      canRetryAiReview = false;
      canExportReport = false;
      canEditScanLabel = false;
    }
  }

  return (
    <AppShell currentUser={currentUser}>
      <div className="border-b border-white/10 pb-6">
        <Link
          className="inline-flex items-center gap-2 text-sm text-slate-300 transition hover:text-cyan-100"
          href="/scans"
        >
          <ArrowLeft className="h-4 w-4" />
          Scans
        </Link>
        <div className="mt-4 flex flex-col justify-between gap-4 md:flex-row md:items-end">
          <div>
            <p className="text-sm font-medium text-cyan-200">
              {scan.accountName} - {scan.scannerKeyPrefix}
            </p>
            <h1 className="mt-2 text-3xl font-semibold tracking-normal">
              {scanDisplayLabel(scan)}
            </h1>
            <p className="mt-2 text-sm text-slate-300">
              {scan.platform}/{scan.arch} - scanner {scan.scannerVersion}
            </p>
            {canEditScanLabel ? (
              <ScanLabelEditor
                initialLabel={scan.playerLabel}
                scanId={scan.id}
              />
            ) : null}
          </div>
          <div className="flex flex-wrap gap-2">
            {canExportReport ? (
              <ReportExportLinks scanId={scan.id} />
            ) : null}
            <span
              className={`rounded-md border px-3 py-2 text-sm font-semibold ${badgeClass(scan.status)}`}
            >
              {scan.status}
            </span>
            <span
              className={`rounded-md border px-3 py-2 text-sm font-semibold ${badgeClass(scan.maxSeverity)}`}
            >
              {scan.maxSeverity}
            </span>
          </div>
        </div>
      </div>

      <div className="mt-6 grid gap-4 md:grid-cols-3">
        <div className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <Gauge className="h-5 w-5 text-cyan-200" />
          <p className="mt-3 text-sm text-slate-400">Risk Score</p>
          <p className="mt-1 text-2xl font-semibold text-slate-100">
            {scan.riskScore}
          </p>
        </div>
        <div className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <ListChecks className="h-5 w-5 text-teal-200" />
          <p className="mt-3 text-sm text-slate-400">Findings</p>
          <p className="mt-1 text-2xl font-semibold text-slate-100">
            {scan.findings.length}
          </p>
        </div>
        <div className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <Clock className="h-5 w-5 text-amber-200" />
          <p className="mt-3 text-sm text-slate-400">Finished</p>
          <p className="mt-1 text-sm font-semibold text-slate-100">
            {scan.finishedAt
              ? formatJakartaDateTime(scan.finishedAt)
              : "Not finished"}
          </p>
        </div>
      </div>

      <ScanDetailTabs canRetryAiReview={canRetryAiReview} scan={scan} />
    </AppShell>
  );
}
