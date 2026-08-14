"use client";

import { Download } from "lucide-react";
import { scanExportUrl } from "@/lib/api";
import { useToast } from "@/components/ui/toast";

export function ReportExportLinks({ scanId }: { scanId: string }) {
  const toast = useToast();

  return (
    <>
      <a
        className="inline-flex items-center gap-2 rounded-md border border-cyan-300/30 bg-cyan-400/10 px-3 py-2 text-sm font-semibold text-cyan-100 transition hover:bg-cyan-400/16"
        href={scanExportUrl(scanId, "html")}
        onClick={() => toast.info("Preparing HTML report download.")}
      >
        <Download className="h-4 w-4" />
        HTML report
      </a>
      <a
        className="inline-flex items-center gap-2 rounded-md border border-white/10 px-3 py-2 text-sm font-semibold text-slate-200 transition hover:bg-white/8"
        href={scanExportUrl(scanId, "json")}
        onClick={() => toast.info("Preparing JSON report download.")}
      >
        <Download className="h-4 w-4" />
        JSON report
      </a>
    </>
  );
}
