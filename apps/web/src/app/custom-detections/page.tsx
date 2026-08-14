import { Braces, FileSearch, ShieldAlert } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import {
  getAccounts,
  getDetectionRules,
  getExecutorIntelligence
} from "@/lib/api";
import { getCookieHeader, requireCurrentUser } from "@/lib/session";
import { CustomDetectionsManager } from "./custom-detections-manager";

export default async function CustomDetectionsPage() {
  const cookieHeader = await getCookieHeader();
  const currentUser = await requireCurrentUser(cookieHeader);
  const [accounts, rules, executorIntelligence] = await Promise.all([
    getAccounts(cookieHeader),
    getDetectionRules(cookieHeader),
    currentUser.globalRole === "SUPER_ADMIN"
      ? getExecutorIntelligence(cookieHeader).catch(() => null)
      : Promise.resolve(null)
  ]);

  return (
    <AppShell currentUser={currentUser}>
      <div className="flex flex-col justify-between gap-4 border-b border-white/10 pb-6 md:flex-row md:items-center">
        <div>
          <h1 className="mt-2 text-3xl font-semibold tracking-normal">
            Custom Detections
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-300">
            Build process, path, hash, and string signature rules without
            rebuilding the scanner.
          </p>
        </div>

        <div className="flex gap-3">
          <div className="rounded-md border border-white/10 bg-white/5 px-3 py-2">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <Braces className="h-4 w-4 text-cyan-200" />
              Rules
            </div>
            <p className="mt-1 text-lg font-semibold text-slate-100">
              {rules.length}
            </p>
          </div>
          <div className="rounded-md border border-white/10 bg-white/5 px-3 py-2">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <ShieldAlert className="h-4 w-4 text-amber-200" />
              Enabled
            </div>
            <p className="mt-1 text-lg font-semibold text-slate-100">
              {rules.filter((rule) => rule.enabled).length}
            </p>
          </div>
          <div className="rounded-md border border-white/10 bg-white/5 px-3 py-2">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <FileSearch className="h-4 w-4 text-teal-200" />
              Hits
            </div>
            <p className="mt-1 text-lg font-semibold text-slate-100">
              {rules.reduce((total, rule) => total + rule.hitCount, 0)}
            </p>
          </div>
        </div>
      </div>

      <div className="mt-6">
        <CustomDetectionsManager
          accounts={accounts}
          currentUser={currentUser}
          executorIntelligence={executorIntelligence}
          initialRules={rules}
        />
      </div>
    </AppShell>
  );
}
