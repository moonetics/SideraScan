"use client";

import { Ban, Save } from "lucide-react";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";
import { AccountDetail, suspendAccount, updateAccount } from "@/lib/api";
import { useConfirm } from "@/components/ui/confirm";
import { useToast } from "@/components/ui/toast";

type AccountDetailActionsProps = {
  account: AccountDetail;
};

export function AccountDetailActions({ account }: AccountDetailActionsProps) {
  const router = useRouter();
  const confirm = useConfirm();
  const toast = useToast();
  const [error, setError] = useState<string | null>(null);
  const [isPending, setIsPending] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setIsPending(true);

    const form = event.currentTarget;
    const formData = new FormData(form);

    try {
      await updateAccount(account.id, {
        name: String(formData.get("name") ?? ""),
        slug: String(formData.get("slug") ?? "")
      });
      toast.success("Account saved.");
      router.refresh();
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Could not update account";
      setError(message);
      toast.error(message);
    } finally {
      setIsPending(false);
    }
  }

  async function handleSuspend() {
    const ok = await confirm({
      confirmLabel: "Suspend account",
      description: `${account.name} will be suspended. Scanner keys and normal account workflows may stop working for this account.`,
      title: "Suspend account?",
      variant: "danger"
    });

    if (!ok) {
      return;
    }

    setError(null);
    setIsPending(true);

    try {
      await suspendAccount(account.id);
      toast.success(`${account.name} suspended.`);
      router.refresh();
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Could not suspend account";
      setError(message);
      toast.error(message);
    } finally {
      setIsPending(false);
    }
  }

  return (
    <form
      className="rounded-lg border border-white/10 bg-[#172842] p-4"
      onSubmit={handleSubmit}
    >
      <h2 className="text-base font-semibold text-slate-100">Account</h2>
      <p className="mt-1 text-sm text-slate-400">
        Account identity and lifecycle. User access is managed from Users.
      </p>
      {error ? <p className="mt-2 text-sm text-rose-200">{error}</p> : null}
      <div className="mt-4 grid gap-3 md:grid-cols-[1fr_1fr_auto] md:items-end">
        <label className="block text-sm font-medium text-slate-200">
          Name
          <input
            className="mt-2 h-10 w-full rounded-md border border-white/10 bg-slate-950/45 px-3 text-sm text-slate-100 outline-none focus:border-cyan-300/70"
            defaultValue={account.name}
            name="name"
            required
          />
        </label>
        <label className="block text-sm font-medium text-slate-200">
          Slug
          <input
            className="mt-2 h-10 w-full rounded-md border border-white/10 bg-slate-950/45 px-3 font-mono text-sm text-slate-100 outline-none focus:border-cyan-300/70"
            defaultValue={account.slug}
            name="slug"
            required
          />
        </label>
        <div className="flex flex-wrap gap-2">
          <button
            className="inline-flex h-10 items-center gap-2 rounded-md bg-cyan-500 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:opacity-70"
            disabled={isPending}
            type="submit"
          >
            <Save className="h-4 w-4" />
            Save
          </button>
          <button
            className="inline-flex h-10 items-center gap-2 rounded-md border border-amber-300/30 bg-amber-400/10 px-4 text-sm font-semibold text-amber-100 transition hover:bg-amber-400/16 disabled:opacity-70"
            disabled={isPending || account.status === "SUSPENDED"}
            onClick={handleSuspend}
            type="button"
          >
            <Ban className="h-4 w-4" />
            Suspend
          </button>
        </div>
      </div>
    </form>
  );
}
