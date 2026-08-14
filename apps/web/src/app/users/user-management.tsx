"use client";

import Link from "next/link";
import { Ban, Plus, ShieldCheck, Undo2, UserPlus, UserRoundCog } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { FormEvent, useMemo, useState } from "react";
import {
  AccountListItem,
  AccountRole,
  SafeUser,
  assignUserToAccount,
  createUser,
  disableUser,
  enableUser
} from "@/lib/api";
import { formatJakartaDateTime } from "@/lib/date-format";
import { useConfirm } from "@/components/ui/confirm";
import { SelectField } from "@/components/ui/select-field";
import { useToast } from "@/components/ui/toast";

type UserManagementProps = {
  accounts: AccountListItem[];
  initialAccountId?: string;
  users: SafeUser[];
};

function assignmentClass(isAssignedToSelectedAccount: boolean) {
  return isAssignedToSelectedAccount
    ? "border-cyan-300/30 bg-cyan-400/10 text-cyan-100"
    : "border-amber-300/30 bg-amber-400/10 text-amber-100";
}

function statusClass(status: string) {
  return status === "ACTIVE"
    ? "border-emerald-300/30 bg-emerald-400/10 text-emerald-100"
    : "border-slate-300/30 bg-slate-400/10 text-slate-100";
}

function roleLabel(role: string) {
  return role.replace("_", " ");
}

export function UserManagement({
  accounts,
  initialAccountId,
  users
}: UserManagementProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const confirm = useConfirm();
  const toast = useToast();
  const fallbackAccountId = accounts[0]?.id ?? "";
  const [selectedAccountId, setSelectedAccountId] = useState(
    initialAccountId && accounts.some((account) => account.id === initialAccountId)
      ? initialAccountId
      : fallbackAccountId
  );
  const [error, setError] = useState<string | null>(null);
  const [isPending, setIsPending] = useState(false);
  const [roleSelections, setRoleSelections] = useState<Record<string, AccountRole>>({});

  const selectedAccount = useMemo(
    () => accounts.find((account) => account.id === selectedAccountId),
    [accounts, selectedAccountId]
  );

  function updateSelectedAccount(accountId: string) {
    setSelectedAccountId(accountId);
    const params = new URLSearchParams(searchParams.toString());

    if (accountId) {
      params.set("accountId", accountId);
    } else {
      params.delete("accountId");
    }

    router.replace(`/users${params.size > 0 ? `?${params.toString()}` : ""}`);
  }

  async function handleCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setIsPending(true);

    const form = event.currentTarget;
    const formData = new FormData(form);

    try {
      await createUser({
        displayName: String(formData.get("displayName") ?? ""),
        email: String(formData.get("email") ?? ""),
        username: String(formData.get("username") ?? ""),
        password: String(formData.get("password") ?? "")
      });
      form.reset();
      toast.success("User created. Assign account access from the table below.");
      router.refresh();
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Could not create user";
      setError(message);
      toast.error(message);
    } finally {
      setIsPending(false);
    }
  }

  async function handleAssign(userId: string, role: AccountRole) {
    if (!selectedAccountId) {
      setError("Select an account before assigning a user.");
      return;
    }

    setError(null);
    setIsPending(true);

    try {
      await assignUserToAccount(selectedAccountId, { userId, role });
      toast.success(
        `User assigned to ${selectedAccount?.name ?? "selected account"} as ${roleLabel(role)}.`
      );
      router.refresh();
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Could not assign user";
      setError(message);
      toast.error(message);
    } finally {
      setIsPending(false);
    }
  }

  async function handleDisable(user: SafeUser) {
    const ok = await confirm({
      confirmLabel: "Disable user",
      description: `${user.displayName} will no longer be able to login until enabled again.`,
      title: "Disable dashboard user?",
      variant: "danger"
    });

    if (!ok) {
      return;
    }

    setError(null);
    setIsPending(true);

    try {
      await disableUser(user.id);
      toast.success(`${user.displayName} disabled.`);
      router.refresh();
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Could not disable user";
      setError(message);
      toast.error(message);
    } finally {
      setIsPending(false);
    }
  }

  async function handleEnable(user: SafeUser) {
    const ok = await confirm({
      confirmLabel: "Enable user",
      description: `${user.displayName} will be allowed to login again.`,
      title: "Enable dashboard user?"
    });

    if (!ok) {
      return;
    }

    setError(null);
    setIsPending(true);

    try {
      await enableUser(user.id);
      toast.success(`${user.displayName} enabled.`);
      router.refresh();
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Could not enable user";
      setError(message);
      toast.error(message);
    } finally {
      setIsPending(false);
    }
  }

  return (
    <div className="mt-6 grid gap-6">
      <form
        className="rounded-lg border border-white/10 bg-[#172842] p-4"
        onSubmit={handleCreate}
      >
        <h2 className="text-base font-semibold text-slate-100">
          Create dashboard user
        </h2>
        <p className="mt-1 text-sm text-slate-400">
          Create the identity here. Assign account access from the table below.
        </p>
        {error ? <p className="mt-3 text-sm text-rose-200">{error}</p> : null}
        <div className="mt-4 grid gap-3 md:grid-cols-4">
          <input
            className="h-10 rounded-md border border-white/10 bg-slate-950/45 px-3 text-sm text-slate-100 outline-none focus:border-cyan-300/70"
            name="displayName"
            placeholder="Display name"
            required
          />
          <input
            className="h-10 rounded-md border border-white/10 bg-slate-950/45 px-3 text-sm text-slate-100 outline-none focus:border-cyan-300/70"
            name="email"
            placeholder="email@example.com"
            required
            type="email"
          />
          <input
            className="h-10 rounded-md border border-white/10 bg-slate-950/45 px-3 text-sm text-slate-100 outline-none focus:border-cyan-300/70"
            name="username"
            placeholder="username"
            required
          />
          <input
            autoComplete="new-password"
            className="h-10 rounded-md border border-white/10 bg-slate-950/45 px-3 text-sm text-slate-100 outline-none focus:border-cyan-300/70"
            minLength={12}
            name="password"
            placeholder="Initial password, min 12 chars"
            required
            type="password"
          />
        </div>
        <button
          className="mt-4 inline-flex h-10 items-center gap-2 rounded-md bg-teal-400 px-4 text-sm font-semibold text-slate-950 transition hover:bg-teal-300 disabled:opacity-70"
          disabled={isPending}
          type="submit"
        >
          <Plus className="h-4 w-4" />
          Create
        </button>
      </form>

      <section className="overflow-hidden rounded-lg border border-white/10 bg-[#172842]">
        <div className="flex flex-col gap-4 border-b border-white/10 px-4 py-3 lg:flex-row lg:items-end lg:justify-between">
          <div className="flex items-center gap-2">
            <UserRoundCog className="h-4 w-4 text-cyan-200" />
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                Access management
              </h2>
              <p className="mt-1 text-sm text-slate-400">
                Select an account, then assign or change each user role.
              </p>
            </div>
          </div>
          <label className="min-w-72 text-sm font-medium text-slate-200">
            Account
            <SelectField
              disabled={accounts.length === 0}
              onChange={(event) => updateSelectedAccount(event.target.value)}
              value={selectedAccountId}
            >
              {accounts.length === 0 ? (
                <option value="">No accounts available</option>
              ) : (
                accounts.map((account) => (
                  <option key={account.id} value={account.id}>
                    {account.name}
                  </option>
                ))
              )}
            </SelectField>
          </label>
        </div>

        {users.length === 0 ? (
          <div className="px-4 py-8 text-sm text-slate-400">
            No dashboard users created yet.
          </div>
        ) : (
          <div className="divide-y divide-white/10">
            {users.map((user) => {
              const selectedMembership = user.accountMemberships?.find(
                (membership) => membership.accountId === selectedAccountId
              );
              const isAssignedToSelectedAccount = Boolean(selectedMembership);
              const membershipCount = user.accountMembershipCount ?? 0;
              const selectedRole =
                roleSelections[user.id] ?? selectedMembership?.role ?? "VIEWER";

              return (
                <div
                  className="grid gap-4 px-4 py-4 xl:grid-cols-[1.15fr_0.85fr_0.85fr_260px]"
                  key={user.id}
                >
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="font-medium text-slate-100">
                        {user.displayName}
                      </p>
                      <span
                        className={`rounded-md border px-2 py-1 text-xs font-semibold ${statusClass(user.status)}`}
                      >
                        {user.status}
                      </span>
                    </div>
                    <p className="mt-1 text-sm text-slate-400">
                      {user.email}
                    </p>
                    <p className="mt-1 font-mono text-xs text-slate-500">
                      {user.username}
                    </p>
                  </div>

                  <div>
                    <p className="text-xs uppercase text-slate-500">
                      Selected account
                    </p>
                    <span
                      className={`mt-2 inline-flex rounded-md border px-2 py-1 text-xs font-semibold ${assignmentClass(isAssignedToSelectedAccount)}`}
                    >
                      {isAssignedToSelectedAccount
                        ? roleLabel(selectedMembership?.role ?? "VIEWER")
                        : "Unassigned"}
                    </span>
                    <p className="mt-2 text-sm text-slate-400">
                      {selectedAccount?.name ?? "No account selected"}
                    </p>
                  </div>

                  <div>
                    <p className="text-xs uppercase text-slate-500">
                      All access
                    </p>
                    <p className="mt-2 text-sm text-slate-400">
                      {membershipCount} account
                      {membershipCount === 1 ? "" : "s"}
                    </p>
                    <p className="mt-2 text-xs text-slate-500">
                      Created{" "}
                      {user.createdAt
                        ? formatJakartaDateTime(user.createdAt)
                        : "Unknown"}
                    </p>
                  </div>

                  <div className="grid gap-2">
                    {user.globalRole === "SUPER_ADMIN" ? (
                      <p className="rounded-md border border-cyan-300/30 bg-cyan-400/10 px-3 py-2 text-sm text-cyan-100">
                        Super Admin has global access.
                      </p>
                    ) : (
                      <>
                        <div className="grid grid-cols-[1fr_auto] gap-2">
                          <SelectField
                            aria-label={`Role for ${user.displayName}`}
                            name={`role-${user.id}`}
                            onChange={(event) =>
                              setRoleSelections((current) => ({
                                ...current,
                                [user.id]: event.target.value as AccountRole
                              }))
                            }
                            value={selectedRole}
                          >
                            <option value="VIEWER">Viewer</option>
                            <option value="MODERATOR">Moderator</option>
                            <option value="ACCOUNT_OWNER">Account Owner</option>
                          </SelectField>
                          <button
                            className="mt-2 inline-flex h-10 items-center justify-center gap-2 rounded-md bg-cyan-500 px-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:opacity-70"
                            disabled={isPending || !selectedAccountId}
                            onClick={() => handleAssign(user.id, selectedRole)}
                            type="button"
                          >
                            <UserPlus className="h-4 w-4" />
                            {isAssignedToSelectedAccount ? "Change role" : "Assign"}
                          </button>
                        </div>
                        {user.status === "DISABLED" ? (
                          <button
                            className="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-emerald-300/30 bg-emerald-400/10 px-3 text-sm font-semibold text-emerald-100 transition hover:bg-emerald-400/16 disabled:opacity-70"
                            disabled={isPending}
                            onClick={() => handleEnable(user)}
                            type="button"
                          >
                            <Undo2 className="h-4 w-4" />
                            Enable
                          </button>
                        ) : (
                          <button
                            className="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-amber-300/30 bg-amber-400/10 px-3 text-sm font-semibold text-amber-100 transition hover:bg-amber-400/16 disabled:opacity-70"
                            disabled={isPending}
                            onClick={() => handleDisable(user)}
                            type="button"
                          >
                            <Ban className="h-4 w-4" />
                            Disable
                          </button>
                        )}
                      </>
                    )}
                    {user.accountMemberships?.slice(0, 2).map((membership) => (
                      <Link
                        className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-white/5 px-3 py-2 text-xs text-slate-300 transition hover:border-cyan-300/40 hover:text-cyan-100"
                        href={`/accounts/${membership.accountId}`}
                        key={membership.id}
                      >
                        <ShieldCheck className="h-3.5 w-3.5 text-cyan-200" />
                        {membership.account.name}
                      </Link>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
