"use client";

import { Plus } from "lucide-react";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";
import { createAccount } from "@/lib/api";
import { useToast } from "@/components/ui/toast";

export function CreateAccountForm() {
  const router = useRouter();
  const toast = useToast();
  const [error, setError] = useState<string | null>(null);
  const [isPending, setIsPending] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setIsPending(true);

    const form = event.currentTarget;
    const formData = new FormData(form);
    const name = String(formData.get("name") ?? "");
    const slug = String(formData.get("slug") ?? "");

    try {
      await createAccount({
        name,
        slug: slug.trim() ? slug : undefined
      });
      form.reset();
      toast.success(`Account ${name} created.`);
      router.refresh();
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Could not create account";
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
      <div>
        <h2 className="text-base font-semibold text-slate-100">
          Create account
        </h2>
        <p className="mt-1 text-sm text-slate-400">
          Add a client/team account. Scanner keys start in the next phase.
        </p>
      </div>

      {error ? (
        <p className="mt-3 rounded-md border border-rose-400/30 bg-rose-500/12 px-3 py-2 text-sm text-rose-100">
          {error}
        </p>
      ) : null}

      <div className="mt-4 grid gap-3 md:grid-cols-[1fr_220px_auto]">
        <label className="text-sm font-medium text-slate-200">
          Name
          <input
            className="mt-2 h-10 w-full rounded-md border border-white/10 bg-slate-950/45 px-3 text-sm text-slate-100 outline-none focus:border-cyan-300/70"
            name="name"
            placeholder="Moon Security"
            required
          />
        </label>

        <label className="text-sm font-medium text-slate-200">
          Slug
          <input
            className="mt-2 h-10 w-full rounded-md border border-white/10 bg-slate-950/45 px-3 text-sm text-slate-100 outline-none focus:border-cyan-300/70"
            name="slug"
            placeholder="moon-security"
          />
        </label>

        <button
          className="mt-auto inline-flex h-10 items-center justify-center gap-2 rounded-md bg-cyan-500 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-70"
          disabled={isPending}
          type="submit"
        >
          <Plus className="h-4 w-4" />
          {isPending ? "Creating" : "Create"}
        </button>
      </div>
    </form>
  );
}
