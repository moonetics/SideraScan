import Link from "next/link";
import { notFound } from "next/navigation";
import {
  Clock3,
  Fingerprint,
  History,
  ShieldAlert,
  ShieldCheck
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { getAccounts, getDevice } from "@/lib/api";
import { formatJakartaDateTime } from "@/lib/date-format";
import { scanDisplayLabel } from "@/lib/scan-label";
import { getCookieHeader, requireCurrentUser } from "@/lib/session";
import { DeviceMarkActions } from "./device-mark-actions";

function markClass(status?: string | null) {
  if (status === "BANNED") {
    return "border-rose-300/30 bg-rose-400/10 text-rose-100";
  }

  if (status === "SUSPICIOUS") {
    return "border-amber-300/30 bg-amber-400/10 text-amber-100";
  }

  if (status === "TRUSTED" || status === "CLEARED") {
    return "border-emerald-300/30 bg-emerald-400/10 text-emerald-100";
  }

  return "border-slate-300/30 bg-slate-400/10 text-slate-100";
}

export default async function DeviceDetailPage({
  params
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const cookieHeader = await getCookieHeader();
  const currentUser = await requireCurrentUser(cookieHeader);
  const [device, accounts] = await Promise.all([
    getDevice(id, cookieHeader).catch(() => null),
    getAccounts(cookieHeader)
  ]);

  if (!device) {
    notFound();
  }

  return (
    <AppShell currentUser={currentUser}>
      <div className="border-b border-white/10 pb-6">
        <Link
          className="text-sm font-semibold text-cyan-200 transition hover:text-cyan-100"
          href="/devices"
        >
          Devices
        </Link>
        <div className="mt-4 flex flex-col justify-between gap-4 md:flex-row md:items-start">
          <div>
            <p className="text-sm font-medium text-cyan-200">Device / HWID</p>
            <h1 className="mt-2 flex items-center gap-3 text-3xl font-semibold tracking-normal">
              <Fingerprint className="h-7 w-7 text-cyan-200" />
              {device.fingerprintPrefix}
            </h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-300">
              Safe device fingerprint details. Full fingerprint hash and raw
              hardware identifiers are not displayed.
            </p>
          </div>

          <span
            className={`w-fit rounded-md border px-3 py-2 text-sm font-semibold ${markClass(device.currentMark?.status)}`}
          >
            {device.currentMark?.status ?? "NO ACTIVE MARK"}
          </span>
        </div>
      </div>

      <div className="mt-6 grid gap-4 lg:grid-cols-4">
        <div className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <p className="text-xs uppercase text-slate-400">Version</p>
          <p className="mt-2 text-lg font-semibold text-slate-100">
            {device.fingerprintVersion}
          </p>
        </div>
        <div className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <p className="text-xs uppercase text-slate-400">Confidence</p>
          <p className="mt-2 text-lg font-semibold text-slate-100">
            {device.fingerprintConfidence}
          </p>
        </div>
        <div className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <p className="text-xs uppercase text-slate-400">Scans</p>
          <p className="mt-2 text-lg font-semibold text-slate-100">
            {device.scanCount}
          </p>
        </div>
        <div className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <p className="text-xs uppercase text-slate-400">Accounts</p>
          <p className="mt-2 text-lg font-semibold text-slate-100">
            {device.accounts.length}
          </p>
        </div>
      </div>

      <div className="mt-6">
        <DeviceMarkActions
          accounts={accounts}
          currentUser={currentUser}
          device={device}
        />
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <div className="flex items-center gap-3">
            <ShieldAlert className="h-5 w-5 text-amber-200" />
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                Mark history
              </h2>
              <p className="mt-1 text-sm text-slate-400">
                Every mark action requires a reason and audit log.
              </p>
            </div>
          </div>

          <div className="mt-4 space-y-3">
            {device.marks.length === 0 ? (
              <div className="rounded-md border border-emerald-300/20 bg-emerald-400/10 p-4 text-sm text-emerald-100">
                No marks have been created for this device.
              </div>
            ) : (
              device.marks.map((mark) => (
                <div
                  className="rounded-md border border-white/10 bg-slate-950/24 p-3"
                  key={mark.id}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span
                      className={`rounded-md border px-2 py-1 text-xs font-semibold ${markClass(mark.status)}`}
                    >
                      {mark.status}
                    </span>
                    <span className="text-xs text-slate-400">
                      {formatJakartaDateTime(mark.markedAt)}
                    </span>
                  </div>
                  <p className="mt-3 text-sm text-slate-200">{mark.reason}</p>
                  <p className="mt-2 text-xs text-slate-400">
                    {mark.scope}
                    {mark.accountName ? ` - ${mark.accountName}` : ""} by{" "}
                    {mark.markedBy?.displayName ?? "Unknown"}
                  </p>
                  {mark.revokedAt ? (
                    <p className="mt-2 text-xs text-rose-200">
                      Revoked {formatJakartaDateTime(mark.revokedAt)}
                    </p>
                  ) : null}
                </div>
              ))
            )}
          </div>
        </section>

        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <div className="flex items-center gap-3">
            <History className="h-5 w-5 text-cyan-200" />
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                Scan history
              </h2>
              <p className="mt-1 text-sm text-slate-400">
                Scans linked by the same safe fingerprint prefix.
              </p>
            </div>
          </div>

          <div className="mt-4 overflow-hidden rounded-lg border border-white/10">
            {device.scanHistory.length === 0 ? (
              <div className="flex items-center gap-3 px-4 py-8 text-sm text-slate-300">
                <ShieldCheck className="h-5 w-5 text-emerald-200" />
                No scan history available.
              </div>
            ) : (
              device.scanHistory.map((scan) => (
                <Link
                  className="grid grid-cols-[minmax(0,1fr)_110px_90px_160px] items-center border-t border-white/10 px-4 py-3 text-sm first:border-t-0 hover:bg-white/6"
                  href={`/scans/${scan.id}`}
                  key={scan.id}
                >
                  <span className="min-w-0">
                    <span className="block truncate font-medium text-slate-100">
                      {scanDisplayLabel(scan)}
                    </span>
                    <span className="block truncate text-xs text-slate-400">
                      {scan.accountName}
                    </span>
                  </span>
                  <span className={`w-fit rounded-md border px-2 py-1 text-xs font-semibold ${markClass(scan.maxSeverity)}`}>
                    {scan.maxSeverity}
                  </span>
                  <span className="text-slate-300">{scan.riskScore}</span>
                  <span className="flex items-center gap-2 text-xs text-slate-400">
                    <Clock3 className="h-4 w-4 text-cyan-200" />
                    {formatJakartaDateTime(scan.createdAt)}
                  </span>
                </Link>
              ))
            )}
          </div>
        </section>
      </div>
    </AppShell>
  );
}
