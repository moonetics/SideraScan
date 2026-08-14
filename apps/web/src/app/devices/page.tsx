import Link from "next/link";
import { Fingerprint, ShieldAlert, ShieldCheck } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { getDevices } from "@/lib/api";
import { formatJakartaDateTime } from "@/lib/date-format";
import { getCookieHeader, requireCurrentUser } from "@/lib/session";

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

export default async function DevicesPage() {
  const cookieHeader = await getCookieHeader();
  const currentUser = await requireCurrentUser(cookieHeader);
  const devices = await getDevices(cookieHeader);

  return (
    <AppShell currentUser={currentUser}>
      <div className="flex flex-col justify-between gap-4 border-b border-white/10 pb-6 md:flex-row md:items-center">
        <div>
          <p className="text-sm font-medium text-cyan-200">Phase 7</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-normal">
            Devices / HWID
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-300">
            Review safe device fingerprints, scan history, and HWID marks
            without exposing raw hardware identifiers.
          </p>
        </div>

        <div className="flex gap-3">
          <div className="rounded-md border border-white/10 bg-white/5 px-3 py-2">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <Fingerprint className="h-4 w-4 text-cyan-200" />
              Visible devices
            </div>
            <p className="mt-1 text-lg font-semibold text-slate-100">
              {devices.length}
            </p>
          </div>
          <div className="rounded-md border border-white/10 bg-white/5 px-3 py-2">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <ShieldAlert className="h-4 w-4 text-amber-200" />
              Marked
            </div>
            <p className="mt-1 text-lg font-semibold text-slate-100">
              {devices.filter((device) => device.currentMark).length}
            </p>
          </div>
        </div>
      </div>

      <div className="mt-6 overflow-hidden rounded-lg border border-white/10">
        <div className="grid grid-cols-[1.1fr_130px_150px_120px_120px_170px_170px] bg-slate-950/45 px-4 py-3 text-xs font-semibold uppercase text-slate-400">
          <span>Fingerprint</span>
          <span>Confidence</span>
          <span>Current mark</span>
          <span>Scans</span>
          <span>Accounts</span>
          <span>First seen</span>
          <span>Last seen</span>
        </div>

        {devices.length === 0 ? (
          <div className="flex items-center gap-3 px-4 py-8 text-sm text-slate-300">
            <ShieldCheck className="h-5 w-5 text-emerald-200" />
            No devices have been linked to scans yet.
          </div>
        ) : (
          devices.map((device) => (
            <Link
              className="grid grid-cols-[1.1fr_130px_150px_120px_120px_170px_170px] items-center border-t border-white/10 px-4 py-4 text-sm transition hover:bg-white/6"
              href={`/devices/${device.id}`}
              key={device.id}
            >
              <span className="flex min-w-0 items-center gap-3">
                <Fingerprint className="h-4 w-4 shrink-0 text-cyan-200" />
                <span className="truncate font-mono text-slate-100">
                  {device.fingerprintPrefix}
                </span>
              </span>
              <span className="text-slate-300">
                {device.fingerprintConfidence}
              </span>
              <span
                className={`w-fit rounded-md border px-2 py-1 text-xs font-semibold ${markClass(device.currentMark?.status)}`}
              >
                {device.currentMark?.status ?? "NONE"}
              </span>
              <span className="text-slate-300">{device.scanCount}</span>
              <span className="text-slate-300">{device.accounts.length}</span>
              <span className="text-xs text-slate-400">
                {formatJakartaDateTime(device.firstSeenAt)}
              </span>
              <span className="text-xs text-slate-400">
                {formatJakartaDateTime(device.lastSeenAt)}
              </span>
            </Link>
          ))
        )}
      </div>
    </AppShell>
  );
}
