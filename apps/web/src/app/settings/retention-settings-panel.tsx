"use client";

import { useMemo, useState } from "react";
import { DatabaseBackup, RotateCcw, Save, ShieldCheck } from "lucide-react";
import {
  retentionDryRun,
  updateRetentionSettings,
  type RetentionDryRun,
  type RetentionSettings
} from "@/lib/api";
import { formatJakartaDateTime } from "@/lib/date-format";
import { useToast } from "@/components/ui/toast";

type RetentionSettingsPanelProps = {
  initialRetention: RetentionSettings;
};

const fields: Array<{
  key: keyof Pick<
    RetentionSettings,
    | "scanResultsDays"
    | "findingsEvidenceDays"
    | "screenshotsDays"
    | "detectionSamplesDays"
    | "monitoringEventsDays"
    | "securityEventsDays"
    | "auditLogsDays"
  >;
  label: string;
  description: string;
}> = [
  {
    key: "scanResultsDays",
    label: "Scan results",
    description: "Normalized scan result payloads and scan detail data."
  },
  {
    key: "findingsEvidenceDays",
    label: "Findings and evidence",
    description: "Indication rows and evidence metadata references."
  },
  {
    key: "screenshotsDays",
    label: "Screenshot evidence",
    description: "Screenshot storage references and screenshot evidence rows."
  },
  {
    key: "detectionSamplesDays",
    label: "Detection samples",
    description: "Uploaded sample metadata and extracted string previews."
  },
  {
    key: "monitoringEventsDays",
    label: "Monitoring events",
    description: "Operational monitoring rows."
  },
  {
    key: "securityEventsDays",
    label: "Security events",
    description: "Security event history and alert candidates."
  },
  {
    key: "auditLogsDays",
    label: "Audit logs",
    description: "Admin action audit trail."
  }
];

function candidateLabel(key: string) {
  return key
    .replace(/([A-Z])/g, " $1")
    .replace(/^./, (value) => value.toUpperCase());
}

export function RetentionSettingsPanel({
  initialRetention
}: RetentionSettingsPanelProps) {
  const [values, setValues] = useState(initialRetention);
  const [dryRun, setDryRun] = useState<RetentionDryRun | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const [isDryRunning, setIsDryRunning] = useState(false);
  const toast = useToast();
  const payload = useMemo(
    () =>
      Object.fromEntries(
        fields.map((field) => [field.key, Number(values[field.key])])
      ),
    [values]
  );

  async function save() {
    setMessage(null);
    setIsSaving(true);

    try {
      const next = await updateRetentionSettings(payload);
      setValues(next);
      setMessage("Retention settings saved and audited.");
      toast.success("Retention settings saved and audited.");
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Could not save retention settings.";
      setMessage(message);
      toast.error(message);
    } finally {
      setIsSaving(false);
    }
  }

  async function runDryRun() {
    setMessage(null);
    setIsDryRunning(true);

    try {
      const result = await retentionDryRun();
      setDryRun(result);
      setMessage("Dry run complete. No records were deleted.");
      toast.success("Dry run complete. No records were deleted.");
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Could not run dry run.";
      setMessage(message);
      toast.error(message);
    } finally {
      setIsDryRunning(false);
    }
  }

  return (
    <div className="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1.1fr)_minmax(360px,.9fr)]">
      <section className="rounded-lg border border-white/10 bg-[#172842] p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-100">
              <ShieldCheck className="h-5 w-5" />
              <h2 className="text-lg font-semibold">Retention Policy</h2>
            </div>
            <p className="mt-2 text-sm leading-6 text-slate-400">
              Values are stored globally. Cleanup is intentionally dry-run only
              in this phase.
            </p>
          </div>
          <span className="rounded-md border border-emerald-300/30 bg-emerald-400/10 px-2 py-1 text-xs font-semibold text-emerald-100">
            Dry-run only
          </span>
        </div>

        <div className="mt-5 grid gap-3 md:grid-cols-2">
          {fields.map((field) => (
            <label
              className="rounded-lg border border-white/10 bg-slate-950/25 p-4"
              key={field.key}
            >
              <span className="text-sm font-semibold text-slate-100">
                {field.label}
              </span>
              <span className="mt-1 block min-h-10 text-xs leading-5 text-slate-400">
                {field.description}
              </span>
              <div className="mt-3 flex items-center gap-2">
                <input
                  className="h-10 w-28 rounded-md border border-white/10 bg-slate-950/50 px-3 text-sm text-slate-100 outline-none transition focus:border-cyan-300/70"
                  min={1}
                  onChange={(event) =>
                    setValues((current) => ({
                      ...current,
                      [field.key]: Number(event.target.value)
                    }))
                  }
                  type="number"
                  value={values[field.key]}
                />
                <span className="text-sm text-slate-400">days</span>
              </div>
            </label>
          ))}
        </div>

        <div className="mt-5 flex flex-wrap gap-3">
          <button
            className="inline-flex h-10 items-center gap-2 rounded-md border border-cyan-300/30 bg-cyan-400/10 px-4 text-sm font-semibold text-cyan-100 transition hover:bg-cyan-400/16 disabled:cursor-not-allowed disabled:opacity-60"
            disabled={isSaving}
            onClick={save}
            type="button"
          >
            <Save className="h-4 w-4" />
            {isSaving ? "Saving..." : "Save policy"}
          </button>
          <button
            className="inline-flex h-10 items-center gap-2 rounded-md border border-white/10 px-4 text-sm font-semibold text-slate-200 transition hover:bg-white/8 disabled:cursor-not-allowed disabled:opacity-60"
            disabled={isDryRunning}
            onClick={runDryRun}
            type="button"
          >
            <RotateCcw className="h-4 w-4" />
            {isDryRunning ? "Checking..." : "Run dry run"}
          </button>
        </div>

        {message ? (
          <p className="mt-4 rounded-md border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-200">
            {message}
          </p>
        ) : null}
      </section>

      <section className="rounded-lg border border-white/10 bg-[#172842] p-5">
        <div className="flex items-center gap-2 text-cyan-100">
          <DatabaseBackup className="h-5 w-5" />
          <h2 className="text-lg font-semibold">Dry-run Result</h2>
        </div>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          Candidate counts show what would be eligible for cleanup. Phase 11
          does not delete these records.
        </p>

        {dryRun ? (
          <div className="mt-5 space-y-3">
            <div className="rounded-md border border-emerald-300/20 bg-emerald-400/8 p-3 text-sm text-emerald-100">
              Generated {formatJakartaDateTime(dryRun.generatedAt)}. Deletes
              records: {dryRun.deletesRecords ? "yes" : "no"}.
            </div>
            <div className="overflow-hidden rounded-lg border border-white/10">
              {Object.entries(dryRun.candidates).map(([key, value]) => (
                <div
                  className="flex items-center justify-between border-b border-white/10 px-4 py-3 last:border-b-0"
                  key={key}
                >
                  <span className="text-sm text-slate-300">
                    {candidateLabel(key)}
                  </span>
                  <span className="font-mono text-sm font-semibold text-slate-100">
                    {value}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="mt-5 rounded-lg border border-dashed border-white/15 p-6 text-sm text-slate-400">
            Run dry run to preview retention candidates.
          </div>
        )}
      </section>
    </div>
  );
}
