import { notFound } from "next/navigation";
import { UserRoundCog } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { getAccounts, getUsers } from "@/lib/api";
import { getCookieHeader, requireCurrentUser } from "@/lib/session";
import { UserManagement } from "./user-management";

type UsersPageProps = {
  searchParams: Promise<{
    accountId?: string;
  }>;
};

export default async function UsersPage({ searchParams }: UsersPageProps) {
  const cookieHeader = await getCookieHeader();
  const currentUser = await requireCurrentUser(cookieHeader);
  const { accountId } = await searchParams;

  if (currentUser.globalRole !== "SUPER_ADMIN") {
    notFound();
  }

  const [users, accounts] = await Promise.all([
    getUsers(cookieHeader),
    getAccounts(cookieHeader)
  ]);

  return (
    <AppShell currentUser={currentUser}>
      <div className="flex flex-col justify-between gap-4 border-b border-white/10 pb-6 md:flex-row md:items-center">
        <div>
          <p className="text-sm font-medium text-cyan-200">Access control</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-normal">
            Users
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-300">
            Manage dashboard users globally, then assign them to client
            accounts when they need account-scoped access.
          </p>
        </div>
        <div className="rounded-md border border-white/10 bg-white/5 px-3 py-2">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <UserRoundCog className="h-4 w-4 text-cyan-200" />
            Dashboard users
          </div>
          <p className="mt-1 text-lg font-semibold text-slate-100">
            {users.length}
          </p>
        </div>
      </div>

      <UserManagement
        accounts={accounts}
        initialAccountId={accountId}
        users={users}
      />
    </AppShell>
  );
}
