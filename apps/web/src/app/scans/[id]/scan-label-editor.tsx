"use client";

import { Save } from "lucide-react";
import { useRouter } from "next/navigation";
import type { FormEvent } from "react";
import { useState } from "react";
import { useToast } from "@/components/ui/toast";
import { updateScanLabel } from "@/lib/api";

type ScanLabelEditorProps = {
  initialLabel: string | null;
  scanId: string;
};

export function ScanLabelEditor({
  initialLabel,
  scanId
}: ScanLabelEditorProps) {
  const router = useRouter();
  const toast = useToast();
  const [label, setLabel] = useState(initialLabel ?? "");
  const [pending, setPending] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);

    try {
      await updateScanLabel(scanId, label.trim() === "" ? null : label.trim());
      toast.success("Scan label updated.");
      router.refresh();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not update scan label.");
    } finally {
      setPending(false);
    }
  }

  return (
    <form className="mt-3 flex max-w-md gap-2" onSubmit={handleSubmit}>
      <input
        className="h-10 min-w-0 flex-1 rounded-md border border-white/10 bg-slate-950/60 px-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-500 focus:border-cyan-300"
        maxLength={160}
        onChange={(event) => setLabel(event.target.value)}
        placeholder="Player / Roblox username"
        value={label}
      />
      <button
        className="inline-flex h-10 items-center gap-2 rounded-md bg-cyan-400 px-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
        disabled={pending}
        type="submit"
      >
        <Save className="h-4 w-4" />
        {pending ? "Saving" : "Save"}
      </button>
    </form>
  );
}
