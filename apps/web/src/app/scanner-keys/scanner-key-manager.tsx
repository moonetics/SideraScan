"use client";

import {
  Copy,
  KeyRound,
  RefreshCcw,
  ShieldAlert,
  ShieldCheck,
  Trash2
} from "lucide-react";
import { FormEvent, useMemo, useState } from "react";
import {
  AccountListItem,
  AuthUser,
  ScannerKeyListItem,
  createScannerKey,
  revokeScannerKey,
  rotateScannerKey
} from "@/lib/api";
import { formatJakartaDateTime } from "@/lib/date-format";
import { useConfirm } from "@/components/ui/confirm";
import { SelectField } from "@/components/ui/select-field";
import { useToast } from "@/components/ui/toast";

type ScannerKeyManagerProps = {
  accounts: AccountListItem[];
  currentUser: AuthUser;
  initialScannerKeys: ScannerKeyListItem[];
};

type OneTimeReveal = {
  title: string;
  rawKey: string;
  keyPrefix: string;
};

function statusClass(status: string) {
  if (status === "ACTIVE") {
    return "border-emerald-300/30 bg-emerald-400/10 text-emerald-100";
  }

  if (status === "REVOKED") {
    return "border-rose-300/30 bg-rose-400/10 text-rose-100";
  }

  return "border-amber-300/30 bg-amber-400/10 text-amber-100";
}

function formatDate(value: string | null) {
  return formatJakartaDateTime(value);
}

function versionText(versions: string[]) {
  if (versions.length === 0) {
    return "Any";
  }

  return versions.join(", ");
}

export function ScannerKeyManager({
  accounts,
  currentUser,
  initialScannerKeys
}: ScannerKeyManagerProps) {
  const [scannerKeys, setScannerKeys] = useState(initialScannerKeys);
  const confirm = useConfirm();
  const toast = useToast();
  const [oneTimeReveal, setOneTimeReveal] = useState<OneTimeReveal | null>(
    null
  );
  const [error, setError] = useState<string | null>(null);
  const [copyMessage, setCopyMessage] = useState<string | null>(null);
  const [isPending, setIsPending] = useState(false);
  const isSuperAdmin = currentUser.globalRole === "SUPER_ADMIN";
  const accountById = useMemo(
    () => new Map(accounts.map((account) => [account.id, account])),
    [accounts]
  );
  const manageableAccounts = accounts.filter(
    (account) => isSuperAdmin || account.viewerRole === "ACCOUNT_OWNER"
  );

  function canManageKey(scannerKey: ScannerKeyListItem) {
    const account = accountById.get(scannerKey.accountId);
    return isSuperAdmin || account?.viewerRole === "ACCOUNT_OWNER";
  }

  async function handleCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setIsPending(true);

    const form = event.currentTarget;
    const formData = new FormData(form);
    const accountId = String(formData.get("accountId") ?? "");
    const versions = String(formData.get("allowedScannerVersions") ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    const expiresAtInput = String(formData.get("expiresAt") ?? "");

    try {
      const result = await createScannerKey(accountId, {
        name: String(formData.get("name") ?? ""),
        expiresAt: expiresAtInput
          ? new Date(expiresAtInput).toISOString()
          : null,
        rateLimitPerHour: Number(formData.get("rateLimitPerHour") ?? 60),
        allowedScannerVersions: versions
      });
      setScannerKeys((current) => [result.scannerKey, ...current]);
      setOneTimeReveal({
        title: "New scanner key",
        rawKey: result.rawKey,
        keyPrefix: result.scannerKey.keyPrefix
      });
      setCopyMessage(null);
      form.reset();
      toast.success("Scanner key generated. Copy the raw key now.");
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Could not generate scanner key";
      setError(message);
      toast.error(message);
    } finally {
      setIsPending(false);
    }
  }

  async function handleRotate(scannerKey: ScannerKeyListItem) {
    const ok = await confirm({
      confirmLabel: "Rotate key",
      description: `${scannerKey.name} will receive a new raw key. The old raw key stops working.`,
      title: "Rotate scanner key?"
    });

    if (!ok) {
      return;
    }

    setError(null);
    setIsPending(true);

    try {
      const result = await rotateScannerKey(scannerKey.id);
      setScannerKeys((current) =>
        current.map((item) =>
          item.id === scannerKey.id ? result.scannerKey : item
        )
      );
      setOneTimeReveal({
        title: "Rotated scanner key",
        rawKey: result.rawKey,
        keyPrefix: result.scannerKey.keyPrefix
      });
      setCopyMessage(null);
      toast.success("Scanner key rotated. Copy the new raw key now.");
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Could not rotate scanner key";
      setError(message);
      toast.error(message);
    } finally {
      setIsPending(false);
    }
  }

  async function handleRevoke(scannerKey: ScannerKeyListItem) {
    const ok = await confirm({
      confirmLabel: "Revoke key",
      description: `${scannerKey.name} will no longer be accepted by the scanner.`,
      title: "Revoke scanner key?",
      variant: "danger"
    });

    if (!ok) {
      return;
    }

    setError(null);
    setIsPending(true);

    try {
      const updated = await revokeScannerKey(scannerKey.id);
      setScannerKeys((current) =>
        current.map((item) => (item.id === scannerKey.id ? updated : item))
      );
      toast.success(`${scannerKey.name} revoked.`);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Could not revoke scanner key";
      setError(message);
      toast.error(message);
    } finally {
      setIsPending(false);
    }
  }

  async function copyRawKey() {
    if (!oneTimeReveal) {
      return;
    }

    try {
      await navigator.clipboard.writeText(oneTimeReveal.rawKey);
      setCopyMessage("Copied to clipboard.");
      toast.success("Scanner key copied to clipboard.");
    } catch {
      setCopyMessage("Clipboard permission was denied. Copy the key manually.");
      toast.error("Clipboard permission was denied. Copy the key manually.");
    }
  }

  return (
    <div className="space-y-6">
      {manageableAccounts.length > 0 ? (
        <form
          className="rounded-lg border border-white/10 bg-[#172842] p-4"
          onSubmit={handleCreate}
        >
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Generate scanner key
            </h2>
            <p className="mt-1 text-sm text-slate-400">
              Raw keys are shown once. Store them outside the dashboard.
            </p>
          </div>

          {error ? (
            <p className="mt-3 rounded-md border border-rose-400/30 bg-rose-500/12 px-3 py-2 text-sm text-rose-100">
              {error}
            </p>
          ) : null}

          <div className="mt-4 grid gap-3 lg:grid-cols-[1fr_1fr_150px]">
            <label className="text-sm font-medium text-slate-200">
              Account
              <SelectField name="accountId" required>
                <option value="">Select account</option>
                {manageableAccounts.map((account) => (
                  <option key={account.id} value={account.id}>
                    {account.name}
                  </option>
                ))}
              </SelectField>
            </label>

            <label className="text-sm font-medium text-slate-200">
              Name
              <input
                className="mt-2 h-10 w-full rounded-md border border-white/10 bg-slate-950/45 px-3 text-sm text-slate-100 outline-none focus:border-cyan-300/70"
                name="name"
                placeholder="Event scanner key"
                required
              />
            </label>

            <label className="text-sm font-medium text-slate-200">
              Rate/hour
              <input
                className="mt-2 h-10 w-full rounded-md border border-white/10 bg-slate-950/45 px-3 text-sm text-slate-100 outline-none focus:border-cyan-300/70"
                defaultValue={60}
                min={1}
                name="rateLimitPerHour"
                required
                type="number"
              />
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
              Allowed versions
              <input
                className="mt-2 h-10 w-full rounded-md border border-white/10 bg-slate-950/45 px-3 text-sm text-slate-100 outline-none focus:border-cyan-300/70"
                name="allowedScannerVersions"
                placeholder="0.1.0, 0.1.1"
              />
            </label>
          </div>

          <button
            className="mt-4 inline-flex h-10 items-center gap-2 rounded-md bg-cyan-500 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-70"
            disabled={isPending}
            type="submit"
          >
            <KeyRound className="h-4 w-4" />
            {isPending ? "Generating" : "Generate key"}
          </button>
        </form>
      ) : null}

      {oneTimeReveal ? (
        <div className="rounded-lg border border-amber-300/30 bg-amber-400/10 p-4">
          <div className="flex items-start gap-3">
            <ShieldAlert className="mt-1 h-5 w-5 text-amber-100" />
            <div className="min-w-0 flex-1">
              <h2 className="text-base font-semibold text-amber-50">
                {oneTimeReveal.title}
              </h2>
              <p className="mt-1 text-sm text-amber-100/80">
                This raw scanner key is shown once. It is not stored and cannot
                be viewed again.
              </p>
              <div className="mt-3 overflow-x-auto rounded-md border border-amber-200/20 bg-slate-950/60 px-3 py-2 font-mono text-sm text-amber-50">
                {oneTimeReveal.rawKey}
              </div>
              <button
                className="mt-3 inline-flex h-9 items-center gap-2 rounded-md bg-amber-300 px-3 text-sm font-semibold text-slate-950 transition hover:bg-amber-200"
                onClick={copyRawKey}
                type="button"
              >
                <Copy className="h-4 w-4" />
                Copy once
              </button>
              {copyMessage ? (
                <p className="mt-2 text-sm text-amber-100/85">
                  {copyMessage}
                </p>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}

      <div className="overflow-hidden rounded-lg border border-white/10">
        <div className="grid grid-cols-[1.1fr_1fr_120px_130px_100px_150px_150px] bg-slate-950/45 px-4 py-3 text-xs font-semibold uppercase text-slate-400">
          <span>Name</span>
          <span>Account</span>
          <span>Prefix</span>
          <span>Status</span>
          <span>Usage</span>
          <span>Last used</span>
          <span>Actions</span>
        </div>

        {scannerKeys.length === 0 ? (
          <div className="flex items-center gap-3 px-4 py-8 text-sm text-slate-300">
            <ShieldCheck className="h-5 w-5 text-cyan-200" />
            No scanner keys visible for this user.
          </div>
        ) : (
          scannerKeys.map((scannerKey) => (
            <div
              className="grid grid-cols-[1.1fr_1fr_120px_130px_100px_150px_150px] items-center border-t border-white/10 px-4 py-4 text-sm"
              key={scannerKey.id}
            >
              <div className="min-w-0">
                <p className="truncate font-medium text-slate-100">
                  {scannerKey.name}
                </p>
                <p className="mt-1 truncate text-xs text-slate-400">
                  Rate {scannerKey.rateLimitPerHour}/h - Versions{" "}
                  {versionText(scannerKey.allowedScannerVersions)}
                </p>
              </div>
              <span className="truncate text-slate-300">
                {scannerKey.accountName}
              </span>
              <span className="font-mono text-slate-200">
                {scannerKey.keyPrefix}
              </span>
              <span
                className={`w-fit rounded-md border px-2 py-1 text-xs font-semibold ${statusClass(scannerKey.status)}`}
              >
                {scannerKey.status}
              </span>
              <span className="text-slate-300">{scannerKey.usageCount}</span>
              <span className="text-xs text-slate-400">
                {formatDate(scannerKey.lastUsedAt)}
              </span>
              <span className="flex gap-2">
                {canManageKey(scannerKey) ? (
                  <>
                    <button
                      className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-white/10 bg-white/8 text-slate-100 transition hover:bg-white/14 disabled:opacity-60"
                      disabled={isPending}
                      onClick={() => void handleRotate(scannerKey)}
                      title="Rotate key"
                      type="button"
                    >
                      <RefreshCcw className="h-4 w-4" />
                    </button>
                    <button
                      className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-rose-300/30 bg-rose-400/10 text-rose-100 transition hover:bg-rose-400/16 disabled:opacity-60"
                      disabled={
                        isPending || scannerKey.status === "REVOKED"
                      }
                      onClick={() => void handleRevoke(scannerKey)}
                      title="Revoke key"
                      type="button"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </>
                ) : (
                  <span className="text-xs text-slate-500">View only</span>
                )}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
