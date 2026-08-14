import Link from "next/link";
import { Building2, ShieldAlert, UsersRound } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { getAccounts } from "@/lib/api";
import { getCookieHeader, requireCurrentUser } from "@/lib/session";
import { CreateAccountForm } from "./account-actions";

function statusClass(status: string) {
  if (status === "ACTIVE") {
    return "border-emerald-300/30 bg-emerald-400/10 text-emerald-100";
  }

  if (status === "SUSPENDED") {
    return "border-amber-300/30 bg-amber-400/10 text-amber-100";
  }

  return "border-slate-300/30 bg-slate-400/10 text-slate-100";
}

export default async function AccountsPage() {
  const cookieHeader = await getCookieHeader();
  const currentUser = await requireCurrentUser(cookieHeader);
  const accounts = await getAccounts(cookieHeader);
  const isSuperAdmin = currentUser.globalRole === "SUPER_ADMIN";

  return (
    <AppShell currentUser={currentUser}>
      <div className="flex flex-col justify-between gap-4 border-b border-white/10 pb-6 md:flex-row md:items-center">
        <div>
          <p className="text-sm font-medium text-cyan-200">Phase 2</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-normal">
            Accounts
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-300">
            Manage client accounts, account roles, and user access boundaries.
          </p>
        </div>

        <div className="flex gap-3">
          <div className="rounded-md border border-white/10 bg-white/5 px-3 py-2">
            <p className="text-xs text-slate-400">Visible accounts</p>
            <p className="text-lg font-semibold text-slate-100">
              {accounts.length}
            </p>
          </div>
          <div className="rounded-md border border-white/10 bg-white/5 px-3 py-2">
            <p className="text-xs text-slate-400">Access mode</p>
            <p className="text-lg font-semibold text-slate-100">
              {isSuperAdmin ? "Global" : "Assigned"}
            </p>
          </div>
        </div>
      </div>

      {isSuperAdmin ? (
        <div className="mt-6">
          <CreateAccountForm />
        </div>
      ) : null}

      <div className="mt-6 overflow-hidden rounded-lg border border-white/10">
        <div className="grid grid-cols-[1.3fr_1fr_140px_120px] bg-slate-950/45 px-4 py-3 text-xs font-semibold uppercase text-slate-400">
          <span>Account</span>
          <span>Slug</span>
          <span>Members</span>
          <span>Status</span>
        </div>

        {accounts.length === 0 ? (
          <div className="flex items-center gap-3 px-4 py-8 text-sm text-slate-300">
            <ShieldAlert className="h-5 w-5 text-amber-200" />
            No accounts available for this user.
          </div>
        ) : (
          accounts.map((account) => (
            <Link
              className="grid grid-cols-[1.3fr_1fr_140px_120px] items-center border-t border-white/10 px-4 py-4 text-sm transition hover:bg-white/6"
              href={`/accounts/${account.id}`}
              key={account.id}
            >
              <span className="flex items-center gap-3 font-medium text-slate-100">
                <Building2 className="h-4 w-4 text-cyan-200" />
                {account.name}
              </span>
              <span className="font-mono text-slate-300">{account.slug}</span>
              <span className="flex items-center gap-2 text-slate-300">
                <UsersRound className="h-4 w-4 text-teal-200" />
                {account.memberCount}
              </span>
              <span
                className={`w-fit rounded-md border px-2 py-1 text-xs font-semibold ${statusClass(account.status)}`}
              >
                {account.status}
              </span>
            </Link>
          ))
        )}
      </div>
    </AppShell>
  );
}

