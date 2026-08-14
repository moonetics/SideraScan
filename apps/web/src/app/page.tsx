import { Activity, Database, ShieldCheck } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { getHealth } from "@/lib/api";
import { getCookieHeader, requireCurrentUser } from "@/lib/session";
import { StatusPill } from "@/components/ui/status-pill";

export default async function Home() {
  const cookieHeader = await getCookieHeader();
  const currentUser = await requireCurrentUser(cookieHeader);

  let apiStatus: "ok" | "error" = "ok";
  let databaseStatus: "ok" | "error" | "unknown" = "unknown";

  try {
    const health = await getHealth();
    databaseStatus = health.database ?? "unknown";
  } catch {
    apiStatus = "error";
  }

  return (
    <AppShell currentUser={currentUser}>
          <div className="flex flex-col justify-between gap-4 border-b border-white/10 pb-6 md:flex-row md:items-center">
            <div>
              <p className="text-sm font-medium text-cyan-200">
                Phase 0 foundation
              </p>
              <h2 className="mt-2 text-3xl font-semibold tracking-normal">
                Scan review dashboard
              </h2>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-300">
                Web foundation is wired to the API health endpoint. Auth,
                accounts, scanner keys, and scan ingestion land in the next
                phases.
              </p>
            </div>

            <div className="flex flex-wrap gap-2">
              <StatusPill status={apiStatus}>API {apiStatus}</StatusPill>
              <StatusPill status={databaseStatus}>
                DB {databaseStatus}
              </StatusPill>
            </div>
          </div>

          <div className="mt-6 grid gap-4 md:grid-cols-3">
            <div className="rounded-lg border border-white/10 bg-[#162544] p-5">
              <Activity className="h-5 w-5 text-cyan-200" />
              <p className="mt-4 text-sm text-slate-300">API Endpoint</p>
              <p className="mt-1 font-mono text-sm text-slate-100">
                /health
              </p>
            </div>
            <div className="rounded-lg border border-white/10 bg-[#162544] p-5">
              <Database className="h-5 w-5 text-teal-200" />
              <p className="mt-4 text-sm text-slate-300">Database</p>
              <p className="mt-1 font-mono text-sm text-slate-100">
                PostgreSQL via Prisma
              </p>
            </div>
            <div className="rounded-lg border border-white/10 bg-[#162544] p-5">
              <ShieldCheck className="h-5 w-5 text-indigo-200" />
              <p className="mt-4 text-sm text-slate-300">Scanner Flow</p>
              <p className="mt-1 font-mono text-sm text-slate-100">
                key - session - result
              </p>
            </div>
          </div>
    </AppShell>
  );
}
