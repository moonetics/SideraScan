import { KeyRound, ShieldCheck } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { getAccounts, getScannerKeys } from "@/lib/api";
import { getCookieHeader, requireCurrentUser } from "@/lib/session";
import { ScannerKeyManager } from "./scanner-key-manager";

export default async function ScannerKeysPage() {
  const cookieHeader = await getCookieHeader();
  const currentUser = await requireCurrentUser(cookieHeader);
  const [accounts, scannerKeys] = await Promise.all([
    getAccounts(cookieHeader),
    getScannerKeys(cookieHeader)
  ]);

  return (
    <AppShell currentUser={currentUser}>
      <div className="flex flex-col justify-between gap-4 border-b border-white/10 pb-6 md:flex-row md:items-center">
        <div>
          <p className="text-sm font-medium text-cyan-200">Phase 3</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-normal">
            Scanner Keys
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-300">
            Generate, rotate, and revoke operational keys used by the Windows
            scanner. These keys do not grant dashboard access.
          </p>
        </div>

        <div className="flex gap-3">
          <div className="rounded-md border border-white/10 bg-white/5 px-3 py-2">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <KeyRound className="h-4 w-4 text-cyan-200" />
              Visible keys
            </div>
            <p className="mt-1 text-lg font-semibold text-slate-100">
              {scannerKeys.length}
            </p>
          </div>
          <div className="rounded-md border border-white/10 bg-white/5 px-3 py-2">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <ShieldCheck className="h-4 w-4 text-teal-200" />
              Storage
            </div>
            <p className="mt-1 text-lg font-semibold text-slate-100">
              Hash only
            </p>
          </div>
        </div>
      </div>

      <div className="mt-6">
        <ScannerKeyManager
          accounts={accounts}
          currentUser={currentUser}
          initialScannerKeys={scannerKeys}
        />
      </div>
    </AppShell>
  );
}
