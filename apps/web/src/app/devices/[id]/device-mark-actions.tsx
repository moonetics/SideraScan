"use client";

import { FormEvent, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  AccountListItem,
  AuthUser,
  DeviceDetail,
  DeviceMark,
  createDeviceMark,
  revokeDeviceMark
} from "@/lib/api";
import { useConfirm } from "@/components/ui/confirm";
import { SelectField } from "@/components/ui/select-field";
import { useToast } from "@/components/ui/toast";
import { scanDisplayLabel } from "@/lib/scan-label";

type DeviceMarkActionsProps = {
  accounts: AccountListItem[];
  currentUser: AuthUser;
  device: DeviceDetail;
};

function canManageAccount(account: AccountListItem, currentUser: AuthUser) {
  return (
    currentUser.globalRole === "SUPER_ADMIN" ||
    account.viewerRole === "ACCOUNT_OWNER"
  );
}

export function DeviceMarkActions({
  accounts,
  currentUser,
  device
}: DeviceMarkActionsProps) {
  const router = useRouter();
  const confirm = useConfirm();
  const toast = useToast();
  const [error, setError] = useState<string | null>(null);
  const [isPending, setIsPending] = useState(false);
  const manageableAccounts = useMemo(
    () =>
      accounts.filter((account) =>
        device.accounts.some((deviceAccount) => deviceAccount.id === account.id)
      ).filter((account) => canManageAccount(account, currentUser)),
    [accounts, currentUser, device.accounts]
  );
  const canCreateGlobal = currentUser.globalRole === "SUPER_ADMIN";
  const canCreateMark = canCreateGlobal || manageableAccounts.length > 0;
  const revokableMarks = device.marks.filter(
    (mark) =>
      !mark.revokedAt &&
      (currentUser.globalRole === "SUPER_ADMIN" ||
        (mark.accountId &&
          manageableAccounts.some((account) => account.id === mark.accountId)))
  );

  async function handleCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setIsPending(true);

    const form = event.currentTarget;
    const formData = new FormData(form);
    const scope = String(formData.get("scope") ?? "ACCOUNT") as
      | "GLOBAL"
      | "ACCOUNT";
    const expiresAtInput = String(formData.get("expiresAt") ?? "");
    const accountId = String(formData.get("accountId") ?? "");

    try {
      await createDeviceMark(device.id, {
        accountId: scope === "ACCOUNT" ? accountId : undefined,
        evidenceScanSessionId:
          String(formData.get("evidenceScanSessionId") ?? "") || undefined,
        expiresAt: expiresAtInput ? new Date(expiresAtInput).toISOString() : null,
        note: String(formData.get("note") ?? "") || undefined,
        reason: String(formData.get("reason") ?? ""),
        scope,
        status: String(formData.get("status") ?? "SUSPICIOUS") as DeviceMark["status"]
      });
      form.reset();
      toast.success("Device mark created.");
      router.refresh();
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Could not create device mark";
      setError(message);
      toast.error(message);
    } finally {
      setIsPending(false);
    }
  }

  async function handleRevoke(markId: string) {
    const ok = await confirm({
      confirmLabel: "Revoke mark",
      description: "This active device mark will stop affecting future scans after you provide a revoke reason.",
      title: "Revoke device mark?",
      variant: "danger"
    });

    if (!ok) {
      return;
    }

    const reason = window.prompt("Reason for revoking this device mark?");

    if (!reason?.trim()) {
      return;
    }

    setError(null);
    setIsPending(true);

    try {
      await revokeDeviceMark(markId, reason);
      toast.success("Device mark revoked.");
      router.refresh();
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Could not revoke device mark";
      setError(message);
      toast.error(message);
    } finally {
      setIsPending(false);
    }
  }

  if (!canCreateMark && revokableMarks.length === 0) {
    return null;
  }

  return (
    <div className="space-y-4">
      {error ? (
        <p className="rounded-md border border-rose-400/30 bg-rose-500/12 px-3 py-2 text-sm text-rose-100">
          {error}
        </p>
      ) : null}

      {canCreateMark ? (
        <form
          className="rounded-lg border border-white/10 bg-[#172842] p-4"
          onSubmit={handleCreate}
        >
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Mark device
            </h2>
            <p className="mt-1 text-sm text-slate-400">
              Mark actions require a reason and are recorded in audit logs.
            </p>
          </div>

          <div className="mt-4 grid gap-3 lg:grid-cols-4">
            <label className="text-sm font-medium text-slate-200">
              Status
              <SelectField name="status" required>
                <option value="SUSPICIOUS">Suspicious</option>
                <option value="BANNED">Banned</option>
                <option value="TRUSTED">Trusted</option>
                <option value="CLEARED">Cleared</option>
              </SelectField>
            </label>

            <label className="text-sm font-medium text-slate-200">
              Scope
              <SelectField name="scope" required>
                {manageableAccounts.length > 0 ? (
                  <option value="ACCOUNT">Account</option>
                ) : null}
                {canCreateGlobal ? <option value="GLOBAL">Global</option> : null}
              </SelectField>
            </label>

            <label className="text-sm font-medium text-slate-200">
              Account
              <SelectField name="accountId">
                <option value="">Global or select account</option>
                {manageableAccounts.map((account) => (
                  <option key={account.id} value={account.id}>
                    {account.name}
                  </option>
                ))}
              </SelectField>
            </label>

            <label className="text-sm font-medium text-slate-200">
              Expires at
              <input
                className="mt-2 h-10 w-full rounded-md border border-white/10 bg-slate-950/45 px-3 text-sm text-slate-100 outline-none focus:border-cyan-300/70"
                name="expiresAt"
                type="datetime-local"
              />
            </label>

            <label className="text-sm font-medium text-slate-200 lg:col-span-2">
              Evidence scan
              <SelectField name="evidenceScanSessionId">
                <option value="">No evidence scan</option>
                {device.scanHistory.map((scan) => (
                  <option key={scan.id} value={scan.id}>
                    {scanDisplayLabel(scan)} - {scan.id}
                  </option>
                ))}
              </SelectField>
            </label>

            <label className="text-sm font-medium text-slate-200 lg:col-span-2">
              Note
              <input
                className="mt-2 h-10 w-full rounded-md border border-white/10 bg-slate-950/45 px-3 text-sm text-slate-100 outline-none focus:border-cyan-300/70"
                name="note"
                placeholder="Optional evidence note"
              />
            </label>

            <label className="text-sm font-medium text-slate-200 lg:col-span-4">
              Reason
              <textarea
                className="mt-2 min-h-24 w-full rounded-md border border-white/10 bg-slate-950/45 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-300/70"
                name="reason"
                placeholder="Why this device should be marked"
                required
              />
            </label>
          </div>

          <button
            className="mt-4 h-10 rounded-md bg-cyan-500 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:opacity-70"
            disabled={isPending}
            type="submit"
          >
            {isPending ? "Saving" : "Create mark"}
          </button>
        </form>
      ) : null}

      {revokableMarks.length > 0 ? (
        <div className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <h2 className="text-base font-semibold text-slate-100">
            Active mark actions
          </h2>
          <div className="mt-3 flex flex-wrap gap-2">
            {revokableMarks.map((mark) => (
              <button
                className="rounded-md border border-rose-300/30 px-3 py-2 text-sm font-semibold text-rose-100 transition hover:bg-rose-400/10 disabled:opacity-70"
                disabled={isPending}
                key={mark.id}
                onClick={() => handleRevoke(mark.id)}
                type="button"
              >
                Revoke {mark.status}
              </button>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}
