import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, Clock, ShieldCheck, UserPlus, UsersRound } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { getAccount } from "@/lib/api";
import { formatJakartaDateTime } from "@/lib/date-format";
import { getCookieHeader, requireCurrentUser } from "@/lib/session";
import { AccountDetailActions } from "./account-detail-actions";

type AccountDetailPageProps = {
  params: Promise<{
    id: string;
  }>;
};

function roleLabel(role: string | null) {
  if (!role) {
    return "Global";
  }

  return role.replace("_", " ");
}

function roleClass(role: string) {
  if (role === "ACCOUNT_OWNER") {
    return "border-cyan-300/30 bg-cyan-400/10 text-cyan-100";
  }

  if (role === "MODERATOR") {
    return "border-teal-300/30 bg-teal-400/10 text-teal-100";
  }

  return "border-slate-300/30 bg-slate-400/10 text-slate-100";
}

function statusClass(status: string) {
  if (status === "ACTIVE") {
    return "border-emerald-300/30 bg-emerald-400/10 text-emerald-100";
  }

  return "border-amber-300/30 bg-amber-400/10 text-amber-100";
}

export default async function AccountDetailPage({
  params
}: AccountDetailPageProps) {
  const { id } = await params;
  const cookieHeader = await getCookieHeader();
  const currentUser = await requireCurrentUser(cookieHeader);
  const isSuperAdmin = currentUser.globalRole === "SUPER_ADMIN";

  let account;

  try {
    account = await getAccount(id, cookieHeader);
  } catch {
    notFound();
  }

  return (
    <AppShell currentUser={currentUser}>
      <div className="border-b border-white/10 pb-6">
        <Link
          className="inline-flex items-center gap-2 text-sm text-slate-300 transition hover:text-cyan-100"
          href="/accounts"
        >
          <ArrowLeft className="h-4 w-4" />
          Accounts
        </Link>
        <div className="mt-4 flex flex-col justify-between gap-4 md:flex-row md:items-end">
          <div>
            <p className="text-sm font-medium text-cyan-200">
              {account.slug}
            </p>
            <h1 className="mt-2 text-3xl font-semibold tracking-normal">
              {account.name}
            </h1>
            <p className="mt-2 text-sm text-slate-300">
              Current access: {roleLabel(account.viewerRole)}
            </p>
          </div>
          <span
            className={`w-fit rounded-md border px-3 py-2 text-sm font-semibold ${statusClass(account.status)}`}
          >
            {account.status}
          </span>
          {isSuperAdmin ? (
            <Link
              className="inline-flex h-10 w-fit items-center gap-2 rounded-md bg-cyan-500 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300"
              href={`/users?accountId=${account.id}`}
            >
              <UserPlus className="h-4 w-4" />
              Manage access
            </Link>
          ) : null}
        </div>
      </div>

      {isSuperAdmin ? (
        <div className="mt-6">
          <AccountDetailActions account={account} />
        </div>
      ) : null}

      <div className="mt-6 grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <section className="rounded-lg border border-white/10 bg-[#172842]">
          <div className="flex items-center gap-2 border-b border-white/10 px-4 py-3">
            <UsersRound className="h-4 w-4 text-teal-200" />
            <h2 className="text-base font-semibold text-slate-100">Users</h2>
            {isSuperAdmin ? (
              <Link
                className="ml-auto inline-flex items-center gap-2 rounded-md border border-cyan-300/30 bg-cyan-400/10 px-3 py-1.5 text-xs font-semibold text-cyan-100 transition hover:bg-cyan-400/16"
                href={`/users?accountId=${account.id}`}
              >
                <UserPlus className="h-3.5 w-3.5" />
                Manage access
              </Link>
            ) : null}
          </div>
          <div className="divide-y divide-white/10">
            {account.users.length === 0 ? (
              <p className="px-4 py-6 text-sm text-slate-400">
                No users assigned to this account yet. Manage account access
                from Users.
              </p>
            ) : (
              account.users.map((membership) => (
                <div
                  className="grid gap-3 px-4 py-4 md:grid-cols-[1fr_auto]"
                  key={membership.id}
                >
                  <div>
                    <p className="font-medium text-slate-100">
                      {membership.user.displayName}
                    </p>
                    <p className="mt-1 text-sm text-slate-400">
                      {membership.user.email}
                    </p>
                  </div>
                  <span
                    className={`h-fit w-fit rounded-md border px-2 py-1 text-xs font-semibold ${roleClass(membership.role)}`}
                  >
                    {roleLabel(membership.role)}
                  </span>
                </div>
              ))
            )}
          </div>
        </section>

        <section className="rounded-lg border border-white/10 bg-[#172842]">
          <div className="flex items-center gap-2 border-b border-white/10 px-4 py-3">
            <Clock className="h-4 w-4 text-amber-200" />
            <h2 className="text-base font-semibold text-slate-100">
              Recent audit
            </h2>
          </div>
          <div className="divide-y divide-white/10">
            {account.auditLogs.length === 0 ? (
              <p className="px-4 py-6 text-sm text-slate-400">
                No audit events yet.
              </p>
            ) : (
              account.auditLogs.map((entry) => (
                <div className="px-4 py-4" key={entry.id}>
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-cyan-200" />
                    <p className="text-sm font-semibold text-slate-100">
                      {entry.action}
                    </p>
                  </div>
                  <p className="mt-1 text-xs text-slate-400">
                    {entry.entityType} - {formatJakartaDateTime(entry.createdAt)}
                  </p>
                </div>
              ))
            )}
          </div>
        </section>
      </div>
    </AppShell>
  );
}
