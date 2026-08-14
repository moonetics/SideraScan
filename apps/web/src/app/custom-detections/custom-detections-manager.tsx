"use client";

import {
  Braces,
  FileSearch,
  Power,
  Radar,
  RefreshCw,
  ShieldCheck,
  Upload,
  WandSparkles
} from "lucide-react";
import { FormEvent, useMemo, useState } from "react";
import {
  AccountListItem,
  AuthUser,
  DetectionRule,
  DetectionRuleType,
  ExecutorIntelligenceOverview,
  DetectionSample,
  DetectionSampleString,
  Severity,
  createDetectionRule,
  disableDetectionRule,
  getDetectionSampleStrings,
  syncExecutorIntelligence,
  updateExecutorIntelligenceSettings,
  uploadDetectionSample
} from "@/lib/api";
import { formatJakartaDateTime } from "@/lib/date-format";
import { useConfirm } from "@/components/ui/confirm";
import { SelectField } from "@/components/ui/select-field";
import { useToast } from "@/components/ui/toast";

type CustomDetectionsManagerProps = {
  accounts: AccountListItem[];
  currentUser: AuthUser;
  executorIntelligence: ExecutorIntelligenceOverview | null;
  initialRules: DetectionRule[];
};

function badgeClass(value: string) {
  if (["SEVERE", "CRITICAL", "DISABLED"].includes(value)) {
    return "border-rose-300/30 bg-rose-400/10 text-rose-100";
  }

  if (["WARNING", "PATH_PATTERN", "STRING_SIGNATURE"].includes(value)) {
    return "border-amber-300/30 bg-amber-400/10 text-amber-100";
  }

  return "border-emerald-300/30 bg-emerald-400/10 text-emerald-100";
}

function lines(value: FormDataEntryValue | null) {
  return String(value ?? "")
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function fileToBase64(file: File) {
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Could not read file"));
    reader.onload = () => resolve(String(reader.result ?? "").split(",").pop() ?? "");
    reader.readAsDataURL(file);
  });
}

export function CustomDetectionsManager({
  accounts,
  currentUser,
  executorIntelligence: initialExecutorIntelligence,
  initialRules
}: CustomDetectionsManagerProps) {
  const [rules, setRules] = useState(initialRules);
  const [executorIntelligence, setExecutorIntelligence] = useState(
    initialExecutorIntelligence
  );
  const [sample, setSample] = useState<DetectionSample | null>(null);
  const [sampleStrings, setSampleStrings] = useState<DetectionSampleString[]>([]);
  const [selectedStrings, setSelectedStrings] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [isPending, setIsPending] = useState(false);
  const [isSyncing, setIsSyncing] = useState(false);
  const [ruleType, setRuleType] = useState<DetectionRuleType>("PROCESS_NAME");
  const confirm = useConfirm();
  const toast = useToast();
  const isSuperAdmin = currentUser.globalRole === "SUPER_ADMIN";
  const manageableAccounts = useMemo(
    () =>
      accounts.filter(
        (account) => isSuperAdmin || account.viewerRole === "ACCOUNT_OWNER"
      ),
    [accounts, isSuperAdmin]
  );
  const canMutate = isSuperAdmin || manageableAccounts.length > 0;

  async function handleSyncExecutorIntel() {
    setError(null);
    setIsSyncing(true);

    try {
      const overview = await syncExecutorIntelligence();
      setExecutorIntelligence(overview);
      if (overview.syncStatus === "cooldown") {
        toast.info("Executor intelligence was synced recently; using cached rules.");
      } else {
        toast.success(
          `Executor intelligence synced: ${overview.counts.windowsItems} Windows items, ${overview.counts.generatedRules} rules.`
        );
      }
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Could not sync executor intelligence";
      setError(message);
      toast.error(message);
    } finally {
      setIsSyncing(false);
    }
  }

  async function handleToggleExecutorIntel() {
    if (!executorIntelligence) {
      return;
    }

    setError(null);
    setIsSyncing(true);

    try {
      const overview = await updateExecutorIntelligenceSettings({
        enabled: !executorIntelligence.settings.enabled
      });
      setExecutorIntelligence(overview);
      toast.success(
        overview.settings.enabled
          ? "Executor intelligence enabled."
          : "Executor intelligence disabled."
      );
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Could not update executor intelligence";
      setError(message);
      toast.error(message);
    } finally {
      setIsSyncing(false);
    }
  }

  function scopeFromForm(formData: FormData) {
    const scope = String(formData.get("scope") ?? "ACCOUNT") as
      | "GLOBAL"
      | "ACCOUNT";
    const accountId = String(formData.get("accountId") ?? "");

    return {
      accountId: scope === "ACCOUNT" ? accountId : undefined,
      scope
    };
  }

  function configFromForm(type: DetectionRuleType, formData: FormData) {
    if (type === "PROCESS_NAME") {
      return {
        matchMode: String(formData.get("matchMode") ?? "contains"),
        processNames: lines(formData.get("patterns"))
      };
    }

    if (type === "FILE_HASH") {
      return {
        algorithm: "sha256",
        hashes: lines(formData.get("patterns"))
      };
    }

    if (type === "PATH_PATTERN") {
      return {
        matchMode: String(formData.get("matchMode") ?? "contains"),
        patterns: lines(formData.get("patterns"))
      };
    }

    const selected = sampleStrings.filter((item) => selectedStrings.has(item.id));

    return {
      clientName: String(formData.get("clientName") ?? "") || undefined,
      strings: selected.map((item) => ({
        preview: item.preview,
        valueHash: item.valueHash
      })),
      targetProcessNames: lines(formData.get("targetProcessNames"))
    };
  }

  async function handleCreateRule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setIsPending(true);

    const form = event.currentTarget;
    const formData = new FormData(form);
    const type = String(formData.get("type") ?? ruleType) as DetectionRuleType;

    try {
      const rule = await createDetectionRule({
        ...scopeFromForm(formData),
        category: "CUSTOM_DETECTION",
        enabled: true,
        name: String(formData.get("name") ?? ""),
        ruleConfig: configFromForm(type, formData),
        severity: String(formData.get("severity") ?? "WARNING") as Severity,
        type
      });
      setRules((current) => [rule, ...current]);
      form.reset();
      setRuleType("PROCESS_NAME");
      setSelectedStrings(new Set());
      toast.success(`Detection rule ${rule.name} created.`);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Could not create detection rule";
      setError(message);
      toast.error(message);
    } finally {
      setIsPending(false);
    }
  }

  async function handleDisable(rule: DetectionRule) {
    const ok = await confirm({
      confirmLabel: "Disable rule",
      description: `${rule.name} will be removed from scanner config for future scans.`,
      title: "Disable detection rule?",
      variant: "danger"
    });

    if (!ok) {
      return;
    }

    setError(null);
    setIsPending(true);

    try {
      const updated = await disableDetectionRule(rule.id);
      setRules((current) =>
        current.map((item) => (item.id === updated.id ? updated : item))
      );
      toast.success(`${rule.name} disabled.`);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Could not disable detection rule";
      setError(message);
      toast.error(message);
    } finally {
      setIsPending(false);
    }
  }

  async function handleUpload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setIsPending(true);

    const form = event.currentTarget;
    const formData = new FormData(form);
    const file = formData.get("sample") as File | null;

    if (!file || file.size === 0) {
      setError("Choose a sample file first");
      setIsPending(false);
      return;
    }

    try {
      const uploaded = await uploadDetectionSample({
        accountId: String(formData.get("accountId") ?? "") || undefined,
        contentBase64: await fileToBase64(file),
        fileName: file.name
      });
      const extracted = await getDetectionSampleStrings(uploaded.id);
      setSample(extracted.sample);
      setSampleStrings(extracted.strings);
      setSelectedStrings(new Set());
      form.reset();
      toast.success(`Extracted ${extracted.strings.length} string previews.`);
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Could not upload or extract sample strings";
      setError(message);
      toast.error(message);
    } finally {
      setIsPending(false);
    }
  }

  function toggleString(id: string) {
    setSelectedStrings((current) => {
      const next = new Set(current);

      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }

      return next;
    });
  }

  return (
    <div className="space-y-6">
      {error ? (
        <p className="rounded-md border border-rose-400/30 bg-rose-500/12 px-3 py-2 text-sm text-rose-100">
          {error}
        </p>
      ) : null}

      {isSuperAdmin && executorIntelligence ? (
        <section className="rounded-lg border border-cyan-300/15 bg-[#172842] p-4">
          <div className="flex flex-col justify-between gap-4 md:flex-row md:items-start">
            <div className="flex items-start gap-3">
              <Radar className="mt-1 h-5 w-5 text-cyan-200" />
              <div>
                <h2 className="text-base font-semibold text-slate-100">
                  Executor Intelligence
                </h2>
                <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-400">
                  Community executor status feed converted into conservative
                  scanner rules. A name match is advisory context; warning
                  requires supporting signals.
                </p>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                className="inline-flex h-10 items-center gap-2 rounded-md border border-white/10 px-3 text-sm font-semibold text-slate-100 transition hover:bg-white/8 disabled:opacity-60"
                disabled={isSyncing}
                onClick={handleToggleExecutorIntel}
                type="button"
              >
                <ShieldCheck className="h-4 w-4" />
                {executorIntelligence.settings.enabled ? "Disable" : "Enable"}
              </button>
              <button
                className="inline-flex h-10 items-center gap-2 rounded-md bg-cyan-500 px-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:opacity-60"
                disabled={isSyncing || !executorIntelligence.settings.enabled}
                onClick={handleSyncExecutorIntel}
                type="button"
              >
                <RefreshCw className={`h-4 w-4 ${isSyncing ? "animate-spin" : ""}`} />
                Sync now
              </button>
            </div>
          </div>

          <div className="mt-4 grid gap-3 md:grid-cols-4">
            {[
              ["Status", executorIntelligence.settings.enabled ? "Enabled" : "Disabled"],
              ["Windows executors", executorIntelligence.counts.windowsItems],
              ["Generated rules", executorIntelligence.counts.generatedRules],
              [
                "Last sync",
                executorIntelligence.settings.lastSuccessAt
                  ? formatJakartaDateTime(executorIntelligence.settings.lastSuccessAt)
                  : "Never"
              ]
            ].map(([label, value]) => (
              <div
                className="rounded-md border border-white/10 bg-slate-950/24 px-3 py-2"
                key={String(label)}
              >
                <p className="text-xs text-slate-400">{label}</p>
                <p className="mt-1 truncate text-sm font-semibold text-slate-100">
                  {String(value)}
                </p>
              </div>
            ))}
          </div>

          {executorIntelligence.settings.lastError ? (
            <p className="mt-3 rounded-md border border-amber-300/30 bg-amber-400/10 px-3 py-2 text-sm text-amber-100">
              Last sync error: {executorIntelligence.settings.lastError}
            </p>
          ) : null}

          <div className="mt-4 overflow-hidden rounded-lg border border-white/10">
            <div className="grid grid-cols-[1fr_120px_120px_120px_120px] bg-slate-950/45 px-4 py-3 text-xs font-semibold uppercase text-slate-400">
              <span>Executor</span>
              <span>Type</span>
              <span>Detected</span>
              <span>Status</span>
              <span>Source</span>
            </div>
            {executorIntelligence.items.length === 0 ? (
              <div className="px-4 py-6 text-sm text-slate-300">
                No executor intelligence has been synced yet.
              </div>
            ) : (
              executorIntelligence.items.slice(0, 12).map((item) => (
                <div
                  className="grid grid-cols-[1fr_120px_120px_120px_120px] items-center border-t border-white/10 px-4 py-3 text-sm"
                  key={item.id}
                >
                  <span className="min-w-0">
                    <span className="block truncate font-medium text-slate-100">
                      {item.title}
                    </span>
                    <span className="mt-1 block truncate text-xs text-slate-400">
                      {item.websiteHost ?? item.slug}
                    </span>
                  </span>
                  <span className="text-xs text-slate-300">
                    {item.extype ?? "unknown"}
                  </span>
                  <span
                    className={`w-fit rounded-md border px-2 py-1 text-xs font-semibold ${
                      item.detected
                        ? "border-amber-300/30 bg-amber-400/10 text-amber-100"
                        : "border-emerald-300/30 bg-emerald-400/10 text-emerald-100"
                    }`}
                  >
                    {item.detected ? "Detected" : "No"}
                  </span>
                  <span className="text-xs text-slate-300">
                    {item.updateStatus ? "Working" : "Updating"}
                  </span>
                  <span className="truncate text-xs text-slate-400">
                    {item.sourceName}
                  </span>
                </div>
              ))
            )}
          </div>

          <p className="mt-3 text-xs leading-5 text-slate-500">
            Attribution: {executorIntelligence.attribution}. SideraScan does not
            download or run executor binaries, and intelligence matches never
            auto-ban players.
          </p>
        </section>
      ) : null}

      {canMutate ? (
        <div className="grid gap-6 xl:grid-cols-[0.95fr_1.05fr]">
          <form
            className="rounded-lg border border-white/10 bg-[#172842] p-4"
            onSubmit={handleCreateRule}
          >
            <div className="flex items-start gap-3">
              <Braces className="mt-1 h-5 w-5 text-cyan-200" />
              <div>
                <h2 className="text-base font-semibold text-slate-100">
                  Create rule
                </h2>
                <p className="mt-1 text-sm text-slate-400">
                  Rules are sent to scanner config after they are enabled.
                </p>
              </div>
            </div>

            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <label className="text-sm font-medium text-slate-200">
                Name
                <input
                  className="mt-2 h-10 w-full rounded-md border border-white/10 bg-slate-950/45 px-3 text-sm text-slate-100 outline-none focus:border-cyan-300/70"
                  name="name"
                  placeholder="Known executor process"
                  required
                />
              </label>
              <label className="text-sm font-medium text-slate-200">
                Type
                <SelectField
                  name="type"
                  onChange={(event) =>
                    setRuleType(event.target.value as DetectionRuleType)
                  }
                  value={ruleType}
                >
                  <option value="PROCESS_NAME">Process name</option>
                  <option value="PATH_PATTERN">Path pattern</option>
                  <option value="FILE_HASH">File hash</option>
                  <option value="STRING_SIGNATURE">String signature</option>
                </SelectField>
              </label>
              <label className="text-sm font-medium text-slate-200">
                Severity
                <SelectField name="severity" required>
                  <option value="WARNING">Warning</option>
                  <option value="SEVERE">Severe</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="INFO">Info</option>
                </SelectField>
              </label>
              <label className="text-sm font-medium text-slate-200">
                Scope
                <SelectField name="scope" required>
                  {manageableAccounts.length > 0 ? (
                    <option value="ACCOUNT">Account</option>
                  ) : null}
                  {isSuperAdmin ? <option value="GLOBAL">Global</option> : null}
                </SelectField>
              </label>
              <label className="text-sm font-medium text-slate-200 md:col-span-2">
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
              {ruleType !== "STRING_SIGNATURE" ? (
                <>
                  {ruleType !== "FILE_HASH" ? (
                    <label className="text-sm font-medium text-slate-200 md:col-span-2">
                      Match mode
                      <SelectField name="matchMode" required>
                        <option value="contains">Contains</option>
                        <option value="exact">Exact</option>
                        <option value="regex">Regex</option>
                        {ruleType === "PATH_PATTERN" ? (
                          <option value="glob">Glob</option>
                        ) : null}
                      </SelectField>
                    </label>
                  ) : null}
                  <label className="text-sm font-medium text-slate-200 md:col-span-2">
                    Values
                    <textarea
                      className="mt-2 min-h-28 w-full rounded-md border border-white/10 bg-slate-950/45 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-300/70"
                      name="patterns"
                      placeholder="One value per line or comma separated"
                      required
                    />
                  </label>
                </>
              ) : (
                <>
                  <label className="text-sm font-medium text-slate-200">
                    Client name
                    <input
                      className="mt-2 h-10 w-full rounded-md border border-white/10 bg-slate-950/45 px-3 text-sm text-slate-100 outline-none focus:border-cyan-300/70"
                      name="clientName"
                      placeholder="Executor/client label"
                    />
                  </label>
                  <label className="text-sm font-medium text-slate-200">
                    Target processes
                    <input
                      className="mt-2 h-10 w-full rounded-md border border-white/10 bg-slate-950/45 px-3 text-sm text-slate-100 outline-none focus:border-cyan-300/70"
                      name="targetProcessNames"
                      placeholder="RobloxPlayerBeta.exe"
                    />
                  </label>
                  <div className="rounded-md border border-white/10 bg-slate-950/24 p-3 text-sm text-slate-300 md:col-span-2">
                    Selected strings: {selectedStrings.size}
                  </div>
                </>
              )}
            </div>

            <button
              className="mt-4 inline-flex h-10 items-center gap-2 rounded-md bg-cyan-500 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:opacity-70"
              disabled={isPending}
              type="submit"
            >
              <WandSparkles className="h-4 w-4" />
              Create rule
            </button>
          </form>

          <form
            className="rounded-lg border border-white/10 bg-[#172842] p-4"
            onSubmit={handleUpload}
          >
            <div className="flex items-start gap-3">
              <Upload className="mt-1 h-5 w-5 text-cyan-200" />
              <div>
                <h2 className="text-base font-semibold text-slate-100">
                  String Builder
                </h2>
                <p className="mt-1 text-sm text-slate-400">
                  Upload a sample to extract printable string previews. Raw
                  bytes are purged after extraction.
                </p>
              </div>
            </div>

            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <label className="text-sm font-medium text-slate-200">
                Account
                <SelectField name="accountId">
                  <option value="">No account / global sample</option>
                  {manageableAccounts.map((account) => (
                    <option key={account.id} value={account.id}>
                      {account.name}
                    </option>
                  ))}
                </SelectField>
              </label>
              <label className="text-sm font-medium text-slate-200">
                Sample
                <input
                  className="mt-2 block h-10 w-full rounded-md border border-white/10 bg-slate-950/45 px-3 py-2 text-sm text-slate-100 file:mr-3 file:rounded-md file:border-0 file:bg-cyan-500 file:px-3 file:py-1 file:text-xs file:font-semibold file:text-slate-950"
                  name="sample"
                  required
                  type="file"
                />
              </label>
            </div>

            <button
              className="mt-4 inline-flex h-10 items-center gap-2 rounded-md bg-cyan-500 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:opacity-70"
              disabled={isPending}
              type="submit"
            >
              <FileSearch className="h-4 w-4" />
              Upload and extract
            </button>

            {sample ? (
              <div className="mt-4 rounded-md border border-white/10 bg-slate-950/24 p-3 text-sm text-slate-300">
                {sample.fileName} - {sample.stringCount} strings -{" "}
                {sample.status}
              </div>
            ) : null}
          </form>
        </div>
      ) : null}

      {sampleStrings.length > 0 ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <h2 className="text-base font-semibold text-slate-100">
            Extracted strings
          </h2>
          <div className="mt-4 max-h-96 overflow-auto rounded-lg border border-white/10">
            {sampleStrings.slice(0, 120).map((item) => (
              <button
                className={`grid w-full grid-cols-[48px_minmax(0,1fr)_90px] items-center gap-3 border-t border-white/10 px-4 py-3 text-left text-sm first:border-t-0 hover:bg-white/6 ${
                  selectedStrings.has(item.id) ? "bg-cyan-400/10" : ""
                }`}
                key={item.id}
                onClick={() => toggleString(item.id)}
                type="button"
              >
                <span className="text-xs font-semibold text-cyan-100">
                  {selectedStrings.has(item.id) ? "Yes" : "No"}
                </span>
                <span className="truncate font-mono text-slate-200">
                  {item.preview}
                </span>
                <span className="text-xs text-slate-400">{item.length}</span>
              </button>
            ))}
          </div>
        </section>
      ) : null}

      <section className="overflow-hidden rounded-lg border border-white/10">
        <div className="grid grid-cols-[1fr_125px_140px_120px_90px_110px_150px] bg-slate-950/45 px-4 py-3 text-xs font-semibold uppercase text-slate-400">
          <span>Rule</span>
          <span>Type</span>
          <span>Scope</span>
          <span>Severity</span>
          <span>Hits</span>
          <span>Status</span>
          <span>Updated</span>
        </div>
        {rules.length === 0 ? (
          <div className="px-4 py-8 text-sm text-slate-300">
            No detection rules have been created yet.
          </div>
        ) : (
          rules.map((rule) => (
            <div
              className="grid grid-cols-[1fr_125px_140px_120px_90px_110px_150px] items-center border-t border-white/10 px-4 py-4 text-sm"
              key={rule.id}
            >
              <span className="min-w-0">
                <span className="block truncate font-medium text-slate-100">
                  {rule.name}
                </span>
                <span className="mt-1 block truncate text-xs text-slate-400">
                  {rule.accountName ?? "Global"}
                </span>
              </span>
              <span className="text-xs text-slate-300">{rule.type}</span>
              <span className="text-xs text-slate-300">{rule.scope}</span>
              <span
                className={`w-fit rounded-md border px-2 py-1 text-xs font-semibold ${badgeClass(rule.severity)}`}
              >
                {rule.severity}
              </span>
              <span className="text-slate-300">{rule.hitCount}</span>
              <span className="flex items-center gap-2">
                <span
                  className={`rounded-md border px-2 py-1 text-xs font-semibold ${
                    rule.enabled
                      ? "border-emerald-300/30 bg-emerald-400/10 text-emerald-100"
                      : "border-slate-300/30 bg-slate-400/10 text-slate-100"
                  }`}
                >
                  {rule.enabled ? "Enabled" : "Disabled"}
                </span>
                {rule.managedBy ? (
                  <span className="rounded-md border border-cyan-300/30 bg-cyan-400/10 px-2 py-1 text-xs font-semibold text-cyan-100">
                    Managed
                  </span>
                ) : rule.enabled && canMutate ? (
                  <button
                    className="rounded-md border border-white/10 p-1.5 text-slate-300 transition hover:bg-white/8"
                    disabled={isPending}
                    onClick={() => handleDisable(rule)}
                    title="Disable rule"
                    type="button"
                  >
                    <Power className="h-4 w-4" />
                  </button>
                ) : null}
              </span>
              <span className="text-xs text-slate-400">
                {formatJakartaDateTime(rule.updatedAt)}
              </span>
            </div>
          ))
        )}
      </section>
    </div>
  );
}
