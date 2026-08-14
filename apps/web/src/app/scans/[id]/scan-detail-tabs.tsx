"use client";

import Link from "next/link";
import type { ColumnDef } from "@tanstack/react-table";
import {
  Boxes,
  Bot,
  CalendarClock,
  CheckCircle2,
  ClipboardList,
  Clock3,
  Database,
  FileSearch,
  Fingerprint,
  Flag,
  Gauge,
  Hash,
  History,
  FolderSearch,
  ListChecks,
  Monitor,
  MonitorCog,
  Network,
  PackageOpen,
  Puzzle,
  Power,
  Rocket,
  ShieldAlert,
  Sparkles,
  TerminalSquare,
  Trash2,
  XCircle,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useMemo, useState } from "react";
import { DataTable } from "@/components/ui/data-table";
import { useConfirm } from "@/components/ui/confirm";
import { useToast } from "@/components/ui/toast";
import { retryAiReview, type ScanDetail } from "@/lib/api";
import { formatMaybeJakartaDateTime } from "@/lib/date-format";

type ScanDetailTabsProps = {
  canRetryAiReview: boolean;
  scan: ScanDetail;
};

type JsonRow = Record<string, unknown>;
type TabKey =
  | "overview"
  | "aiReview"
  | "device"
  | "launcherProfiles"
  | "clientMods"
  | "process"
  | "processTimes"
  | "explore"
  | "fileLogs"
  | "utilities"
  | "windows"
  | "loadedModules"
  | "handles"
  | "persistence"
  | "drivers"
  | "eventLogs"
  | "executionArtifacts"
  | "fileTriage"
  | "networkForensics"
  | "forensicTimeline"
  | "evidence"
  | "audit"
  | "indications";

const tabs: Array<{ key: TabKey; label: string }> = [
  { key: "overview", label: "Overview" },
  { key: "aiReview", label: "AI Review" },
  { key: "device", label: "Device / HWID" },
  { key: "launcherProfiles", label: "Launcher Profiles" },
  { key: "clientMods", label: "Client Mods / Assets" },
  { key: "process", label: "Process Timeline" },
  { key: "processTimes", label: "Process Times" },
  { key: "explore", label: "Explore Files" },
  { key: "fileLogs", label: "Explore File Logs" },
  { key: "utilities", label: "Utilities" },
  { key: "windows", label: "Windows Items" },
  { key: "loadedModules", label: "Loaded DLLs" },
  { key: "handles", label: "Handles" },
  { key: "persistence", label: "Persistence" },
  { key: "drivers", label: "Drivers" },
  { key: "eventLogs", label: "Event Logs" },
  { key: "executionArtifacts", label: "Execution Artifacts" },
  { key: "fileTriage", label: "File Triage" },
  { key: "networkForensics", label: "Network" },
  { key: "forensicTimeline", label: "Forensic Timeline" },
  { key: "evidence", label: "Evidence" },
  { key: "audit", label: "Audit Log" },
  { key: "indications", label: "Indication Log" },
];

const privatePathPattern = /([A-Za-z]:[\\/]+Users[\\/]+)([^\\/]+)([\\/]+)/gi;
const secretPattern =
  /(sds_live_[A-Za-z0-9-]+|sut_[A-Za-z0-9_-]+|snonce_[A-Za-z0-9_-]+)/g;

function maskText(value: string) {
  return value
    .replace(/\bAF-[3-7]\s+review item:\s*/gi, "")
    .replace(/\bAF-[3-7]\b/gi, "Forensic")
    .replace(privatePathPattern, "$1***$3")
    .replace(secretPattern, "[REDACTED]");
}

function formatValue(value: unknown) {
  if (value === null || value === undefined || value === "") {
    return "Unknown";
  }

  if (typeof value === "object") {
    return maskText(JSON.stringify(value));
  }

  return formatMaybeJakartaDateTime(maskText(String(value)));
}

function rowsFrom(value: unknown): JsonRow[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.map((item, index) =>
    item && typeof item === "object" && !Array.isArray(item)
      ? ({ index: index + 1, ...item } as JsonRow)
      : { index: index + 1, value: item },
  );
}

function listFrom(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.map((item) => formatValue(item));
}

function objectFrom(value: unknown): JsonRow {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRow)
    : {};
}

function recommendedActionLabel(value: string) {
  return value
    .toLowerCase()
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function firstValue(row: JsonRow, keys: string[]) {
  for (const key of keys) {
    if (row[key] !== undefined && row[key] !== null && row[key] !== "") {
      return row[key];
    }
  }

  return undefined;
}

function badgeClass(value: string) {
  const normalized = value.toUpperCase();

  if (
    [
      "BANNED",
      "CRITICAL",
      "SEVERE",
      "FAILED",
      "FLAGGED",
      "SUSPICIOUS",
    ].includes(normalized)
  ) {
    return "border-rose-300/30 bg-rose-400/10 text-rose-100";
  }

  if (["WARNING", "PARTIAL", "UNKNOWN", "SKIPPED"].includes(normalized)) {
    return "border-amber-300/30 bg-amber-400/10 text-amber-100";
  }

  if (["REVIEW", "CONTEXT", "OBSERVED"].includes(normalized)) {
    return "border-cyan-300/30 bg-cyan-400/10 text-cyan-100";
  }

  return "border-emerald-300/30 bg-emerald-400/10 text-emerald-100";
}

function TruncatedText({ value }: { value: unknown }) {
  const text = formatValue(value);

  return (
    <span className="block max-w-[34rem] truncate text-slate-200" title={text}>
      {text}
    </span>
  );
}

function Badge({ value }: { value: unknown }) {
  const text = formatValue(value);

  return (
    <span
      className={`inline-flex rounded-md border px-2 py-1 text-xs font-semibold ${badgeClass(text)}`}
    >
      {text}
    </span>
  );
}

function fileActionClass(value: string) {
  const normalized = value.toLowerCase();

  if (normalized.includes("deleted")) {
    return "border-rose-300/40 bg-rose-400/10 text-rose-100";
  }

  if (normalized.includes("renamed") || normalized.includes("moved")) {
    return "border-cyan-300/40 bg-cyan-400/10 text-cyan-100";
  }

  if (normalized.includes("created") || normalized.includes("downloaded")) {
    return "border-emerald-300/40 bg-emerald-400/10 text-emerald-100";
  }

  if (normalized.includes("executed") || normalized.includes("closed")) {
    return "border-amber-300/40 bg-amber-400/10 text-amber-100";
  }

  if (normalized.includes("plugged")) {
    return "border-indigo-300/40 bg-indigo-400/10 text-indigo-100";
  }

  return "border-slate-300/30 bg-slate-400/10 text-slate-100";
}

function FileActionBadge({ value }: { value: unknown }) {
  const text = formatValue(value);

  return (
    <span
      className={`inline-flex rounded-md border px-2 py-1 text-xs font-semibold ${fileActionClass(text)}`}
    >
      {text.replaceAll("_", " ")}
    </span>
  );
}

const countryCodeByName: Record<string, string> = {
  INDONESIA: "ID",
  "UNITED STATES": "US",
  USA: "US",
  JAPAN: "JP",
  SINGAPORE: "SG",
  MALAYSIA: "MY",
  PHILIPPINES: "PH",
  THAILAND: "TH",
  VIETNAM: "VN",
};

const countryNameByCode: Record<string, string> = {
  ID: "Indonesia",
  JP: "Japan",
  MY: "Malaysia",
  PH: "Philippines",
  SG: "Singapore",
  TH: "Thailand",
  US: "United States",
  VN: "Vietnam",
};

function flagFromCode(code: string) {
  if (!/^[A-Z]{2}$/.test(code)) {
    return null;
  }

  return String.fromCodePoint(
    ...code.split("").map((char) => 127397 + char.charCodeAt(0)),
  );
}

function countryDisplay(value: unknown) {
  const text = formatValue(value).trim();
  const normalized = text.toUpperCase();
  const code =
    normalized.length === 2 ? normalized : countryCodeByName[normalized];

  if (!code) {
    return { flag: null, name: text };
  }

  return {
    flag: flagFromCode(code),
    name: countryNameByCode[code] ?? text,
  };
}

function parseDateMs(value: unknown) {
  if (!value) {
    return null;
  }

  const date = new Date(String(value));

  return Number.isNaN(date.getTime()) ? null : date.getTime();
}

function formatDurationMs(value: number) {
  const totalSeconds = Math.max(0, Math.round(value / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (hours > 0) {
    return `${hours}h ${minutes}m ${seconds}s`;
  }

  if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  }

  return `${seconds}s`;
}

function scanDuration(scan: ScanDetail, overview: JsonRow) {
  const startedAt = parseDateMs(scan.startedAt);
  const finishedAt = parseDateMs(scan.finishedAt);

  if (startedAt && finishedAt) {
    return formatDurationMs(finishedAt - startedAt);
  }

  if (startedAt && !finishedAt) {
    return "In progress";
  }

  const uploadedDuration =
    overview.scanDurationMs ??
    overview.durationMs ??
    overview.scanDuration ??
    overview.scanSpeed;

  return formatValue(uploadedDuration);
}

function isNoLike(value: unknown) {
  const text = formatValue(value).trim().toLowerCase();

  return ["no", "false", "0", "clean", "none", "not detected"].includes(text);
}

function isYesLike(value: unknown) {
  const text = formatValue(value).trim().toLowerCase();

  return ["yes", "true", "1", "detected"].includes(text);
}

function column(
  id: string,
  header: string,
  keys: string[],
  variant: "text" | "badge" | "fileAction" = "text",
): ColumnDef<JsonRow> {
  return {
    accessorFn: (row) => formatValue(firstValue(row, keys)),
    cell: ({ row }) =>
      variant === "badge" ? (
        <Badge value={firstValue(row.original, keys)} />
      ) : variant === "fileAction" ? (
        <FileActionBadge value={firstValue(row.original, keys)} />
      ) : (
        <TruncatedText value={firstValue(row.original, keys)} />
      ),
    header,
    id,
  };
}

function listSummary(value: unknown) {
  if (Array.isArray(value)) {
    return value.length > 0
      ? value.map((item) => formatValue(item)).join(", ")
      : "None";
  }

  return formatValue(value);
}

function networkSummaryText(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return "None";
  }

  const summary = value as JsonRow;
  const tcp = Number(summary.tcpCount ?? 0);
  const udp = Number(summary.udpCount ?? 0);
  const remote = Number(summary.remoteCount ?? 0);

  if (tcp === 0 && udp === 0 && remote === 0) {
    return "None";
  }

  return `${tcp} TCP / ${udp} UDP / ${remote} remote`;
}

function displayModuleStatus(row: {
  status?: string | null;
  errorCode?: string | null;
}) {
  if (row.errorCode === "MODULE_WARNING") {
    return "Completed with limited artifacts";
  }

  return row.status ?? "Unknown";
}

function DetailField({
  label,
  value,
  wide = false,
}: {
  label: string;
  value: unknown;
  wide?: boolean;
}) {
  return (
    <div
      className={`rounded-md border border-white/8 bg-slate-950/28 px-3 py-2 ${
        wide ? "md:col-span-2" : ""
      }`}
    >
      <p className="text-[0.68rem] font-semibold uppercase text-slate-500">
        {label}
      </p>
      <p className="mt-1 break-words text-sm text-slate-100">
        {Array.isArray(value) ? listSummary(value) : formatValue(value)}
      </p>
    </div>
  );
}

function ProcessDetailPanel({
  onClose,
  row,
}: {
  onClose: () => void;
  row: JsonRow;
}) {
  const safeJson = maskText(JSON.stringify(row, null, 2));

  return (
    <div className="mt-4 rounded-lg border border-cyan-300/20 bg-slate-950/30 p-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase text-cyan-300">
            Process details
          </p>
          <h3 className="mt-1 text-lg font-semibold text-slate-100">
            {formatValue(firstValue(row, ["processName", "name", "process"]))}
          </h3>
        </div>
        <button
          className="rounded-md border border-white/10 px-3 py-2 text-sm font-semibold text-slate-200 hover:border-cyan-300/40 hover:text-cyan-100"
          onClick={onClose}
          type="button"
        >
          Close
        </button>
      </div>

      <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        <DetailField label="PID" value={row.pid} />
        <DetailField
          label="Parent"
          value={firstValue(row, ["parentName", "parentProcess", "parent"])}
        />
        <DetailField label="Session" value={row.sessionId} />
        <DetailField
          label="Path"
          value={firstValue(row, ["path", "executablePath", "pathMasked"])}
          wide
        />
        <DetailField label="Command line" value={row.commandLine} wide />
        <DetailField label="Working directory" value={row.cwd} wide />
        <DetailField label="Owner" value={row.owner} />
        <DetailField label="Signer" value={row.signer} />
        <DetailField label="Publisher" value={row.publisher} />
        <DetailField label="Signature" value={row.signatureStatus} />
        <DetailField
          label="Network"
          value={networkSummaryText(row.networkSummary)}
        />
        <DetailField label="Confidence" value={row.confidence} />
        <DetailField
          label="Suspicious flags"
          value={row.suspiciousFlags}
          wide
        />
        <DetailField label="Limited reasons" value={row.limitedReasons} wide />
      </div>

      <details className="mt-4 rounded-md border border-white/8 bg-slate-950/35 p-3">
        <summary className="cursor-pointer text-sm font-semibold text-cyan-100">
          Safe metadata JSON
        </summary>
        <pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap text-xs leading-relaxed text-slate-300">
          {safeJson}
        </pre>
      </details>
    </div>
  );
}

function ForensicModeBadge({
  integrity,
  summaryKey = "af3Summary",
}: {
  integrity?: Record<string, unknown>;
  summaryKey?:
    "af3Summary" | "af4Summary" | "af5Summary" | "af6Summary" | "af7Summary";
}) {
  const summary = objectFrom(integrity?.[summaryKey]);
  const reviewMode = formatValue(summary.reviewMode);

  if (reviewMode === "Unknown") {
    return null;
  }

  const label =
    reviewMode === "ai_assisted_full"
      ? "AI-assisted full metadata"
      : "Review-relevant fallback";

  return <Badge value={label} />;
}

function ForensicTuningBadges({
  integrity,
}: {
  integrity?: Record<string, unknown>;
}) {
  const summary = objectFrom(integrity?.af8Summary);

  if (Object.keys(summary).length === 0) {
    return null;
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Badge value={`Context ${formatValue(summary.noiseSuppressedCount)}`} />
      <Badge value={`Review ${formatValue(summary.reviewOnlyCount)}`} />
      <Badge
        value={`Suppressed ${formatValue(summary.benignClassifiedCount)}`}
      />
    </div>
  );
}

function ScanInfoRow({
  icon: Icon,
  label,
  value,
  variant = "text",
}: {
  icon: LucideIcon;
  label: string;
  value: unknown;
  variant?: "text" | "boolean" | "country";
}) {
  const isPositive = variant === "boolean" && isNoLike(value);
  const isNegative = variant === "boolean" && isYesLike(value);
  const country = variant === "country" ? countryDisplay(value) : null;
  const text = country ? country.name : formatValue(value);

  return (
    <div className="flex min-h-9 items-center gap-3 border-b border-white/8 px-4 py-2.5 last:border-b-0">
      <Icon className="h-4 w-4 shrink-0 text-cyan-300" />
      <p className="min-w-0 flex-1 truncate text-sm text-slate-400">{label}</p>
      <p
        className={`flex min-w-0 max-w-[58%] items-center gap-2 text-right text-sm font-semibold ${
          isPositive
            ? "text-emerald-300"
            : isNegative
              ? "text-rose-300"
              : "text-cyan-100"
        }`}
      >
        {isPositive ? (
          <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-300" />
        ) : null}
        {isNegative ? (
          <XCircle className="h-4 w-4 shrink-0 text-rose-300" />
        ) : null}
        {country?.flag ? (
          <span className="text-base leading-none">{country.flag}</span>
        ) : null}
        <span className="truncate" title={text}>
          {text}
        </span>
      </p>
    </div>
  );
}

function ScanInformationPanel({
  rows,
}: {
  rows: Array<{
    icon: LucideIcon;
    label: string;
    value: unknown;
    variant?: "text" | "boolean" | "country";
  }>;
}) {
  return (
    <div className="h-full rounded-lg border border-white/10 bg-slate-950/24">
      <div className="px-4 pb-3 pt-4">
        <h3 className="text-base font-semibold text-slate-100">
          Scan Information
        </h3>
        <p className="mt-1 text-xs text-slate-400">Key facts about the scan.</p>
      </div>
      <div className="border-t border-white/8">
        {rows.map((row) => (
          <ScanInfoRow
            icon={row.icon}
            key={row.label}
            label={row.label}
            value={row.value}
            variant={row.variant}
          />
        ))}
      </div>
    </div>
  );
}

function severityCount(scan: ScanDetail) {
  return {
    clean: scan.findings.filter((finding) => finding.severity === "CLEAN")
      .length,
    warning: scan.findings.filter((finding) => finding.severity === "WARNING")
      .length,
    severe: scan.findings.filter((finding) => finding.severity === "SEVERE")
      .length,
    critical: scan.findings.filter((finding) => finding.severity === "CRITICAL")
      .length,
  };
}

function IndicationGraph({ scan }: { scan: ScanDetail }) {
  const counts = severityCount(scan);
  const rawTotal =
    counts.clean + counts.warning + counts.severe + counts.critical;
  const total = Math.max(1, rawTotal);
  const segments = [
    {
      color: "#34d399",
      label: "Clean",
      value: counts.clean,
    },
    {
      color: "#fbbf24",
      label: "Warning",
      value: counts.warning,
    },
    {
      color: "#fb7185",
      label: "Severe",
      value: counts.severe,
    },
    {
      color: "#e879f9",
      label: "Critical",
      value: counts.critical,
    },
  ];
  let currentAngle = 0;
  const pieStops =
    rawTotal === 0
      ? "#34d399 0deg 360deg"
      : segments
          .filter((segment) => segment.value > 0)
          .map((segment) => {
            const start = currentAngle;
            const end = start + (segment.value / total) * 360;
            currentAngle = end;

            return `${segment.color} ${start}deg ${end}deg`;
          })
          .join(", ");

  return (
    <div className="h-full rounded-lg border border-white/10 bg-slate-950/24 p-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold text-slate-100">
            Indications Graph
          </h3>
          <p className="mt-1 text-xs text-slate-400">
            Visual representation of indications found during the scan.
          </p>
        </div>
      </div>

      <div className="mt-6 flex justify-center">
        <div
          aria-label="Indication severity donut chart"
          className="relative h-52 w-52 rounded-full"
          role="img"
          style={{
            background: `conic-gradient(${pieStops})`,
          }}
        >
          <div className="absolute inset-10 flex flex-col items-center justify-center rounded-full bg-[#172842] shadow-inner shadow-slate-950/50">
            <span className="text-3xl font-semibold text-slate-100">
              {scan.riskScore}
            </span>
            <span className="mt-1 text-xs uppercase text-slate-400">
              Risk score
            </span>
          </div>
        </div>
      </div>

      <div className="mt-5 grid grid-cols-2 gap-2">
        {segments.map((segment) => (
          <div
            className="flex items-center justify-between gap-2 rounded-md border border-white/10 bg-white/5 px-3 py-2"
            key={segment.label}
          >
            <div className="flex items-center gap-2">
              <span
                className="h-2.5 w-2.5 rounded-full"
                style={{ backgroundColor: segment.color }}
              />
              <span className="text-xs text-slate-400">{segment.label}</span>
            </div>
            <p className="text-sm font-semibold text-slate-100">
              {segment.value}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

function OverviewIndicationLog({
  scan,
  onOpenEvidence,
  onOpenFullLog,
}: {
  scan: ScanDetail;
  onOpenEvidence: () => void;
  onOpenFullLog: () => void;
}) {
  const items = scan.findings.slice(0, 6);
  const counts = severityCount(scan);
  const summaries = [
    {
      className: "border-emerald-300/20 bg-emerald-400/10 text-emerald-100",
      label: "Clean",
      value: counts.clean,
    },
    {
      className: "border-amber-300/20 bg-amber-400/10 text-amber-100",
      label: "Warning",
      value: counts.warning,
    },
    {
      className: "border-rose-300/20 bg-rose-400/10 text-rose-100",
      label: "Severe",
      value: counts.severe + counts.critical,
    },
  ];

  return (
    <div className="h-full rounded-lg border border-white/10 bg-slate-950/24 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold text-slate-100">
            Indication Log
          </h3>
          <p className="mt-1 text-xs text-slate-400">
            Detailed log of all indications found during the scan.
          </p>
        </div>
        <button
          className="h-8 rounded-md border border-amber-300 bg-transparent px-3 text-xs font-semibold text-amber-200 transition hover:bg-amber-300/10"
          disabled
          type="button"
        >
          Report Scan
        </button>
      </div>

      <div className="mt-5 grid grid-cols-3 gap-2">
        {summaries.map((summary) => (
          <div
            className={`rounded-md border px-3 py-2 ${summary.className}`}
            key={summary.label}
          >
            <p className="text-xs text-current/75">{summary.label}</p>
            <p className="mt-1 text-base font-semibold">{summary.value}</p>
          </div>
        ))}
      </div>

      <div className="mt-4 max-h-[18rem] space-y-2 overflow-hidden">
        {items.length === 0 ? (
          <div className="rounded-md border border-emerald-300/20 bg-emerald-400/10 px-3 py-4 text-sm text-emerald-100">
            No indications found.
          </div>
        ) : (
          items.map((finding) => (
            <div
              className={`rounded-md border px-3 py-3 ${badgeClass(finding.severity).replace("text-", "text-")}`}
              key={finding.id}
            >
              <div className="flex min-w-0 items-start gap-3">
                {finding.severity === "CLEAN" ? (
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
                ) : finding.severity === "WARNING" ? (
                  <span className="mt-0.5 text-sm font-black leading-none">
                    !
                  </span>
                ) : (
                  <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
                )}
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-semibold text-slate-100">
                    {finding.title}
                  </p>
                  <p className="mt-1 truncate text-xs text-slate-300/80">
                    {finding.message}
                  </p>
                </div>
                <span className="hidden shrink-0 text-xs font-semibold text-current/75 xl:block">
                  {finding.category}
                </span>
              </div>
              {finding.evidence ? (
                <button
                  className="mt-2 max-w-full truncate rounded-md border border-cyan-300/30 bg-cyan-400/10 px-2 py-1 text-left text-xs font-semibold text-cyan-100 transition hover:bg-cyan-400/16"
                  onClick={onOpenEvidence}
                  title={finding.evidence.title}
                  type="button"
                >
                  {finding.evidence.title}
                </button>
              ) : null}
            </div>
          ))
        )}
      </div>
      <button
        className="mt-4 h-9 w-full rounded-md border border-white/10 px-3 text-xs font-semibold text-slate-200 transition hover:bg-white/8"
        onClick={onOpenFullLog}
        type="button"
      >
        View table
      </button>
    </div>
  );
}

function isRobloxFinding(finding: ScanDetail["findings"][number]) {
  const robloxCategories = [
    "LAUNCHER_PROFILE",
    "CLIENT_MOD_ASSET",
    "FILE_LOG",
    "UTILITY",
    "WINDOWS_ITEM",
  ];

  return (
    robloxCategories.includes(finding.category) ||
    finding.sourceModule?.toLowerCase().startsWith("roblox")
  );
}

function SectionHeader({
  icon: Icon,
  title,
  description,
}: {
  icon: typeof ListChecks;
  title: string;
  description: string;
}) {
  return (
    <div className="mb-4 flex items-start gap-3">
      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-cyan-400/12 text-cyan-100">
        <Icon className="h-5 w-5" />
      </div>
      <div>
        <h2 className="text-lg font-semibold text-slate-100">{title}</h2>
        <p className="mt-1 text-sm text-slate-400">{description}</p>
      </div>
    </div>
  );
}

function ReviewList({
  empty,
  items,
  title,
}: {
  empty: string;
  items: string[];
  title: string;
}) {
  return (
    <div className="rounded-md border border-white/10 bg-slate-950/24 p-3">
      <h3 className="text-sm font-semibold text-slate-100">{title}</h3>
      {items.length > 0 ? (
        <ul className="mt-3 space-y-2">
          {items.map((item, index) => (
            <li
              className="rounded-md border border-white/8 bg-white/5 px-3 py-2 text-sm text-slate-200"
              key={`${title}-${index}`}
            >
              {item}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-3 text-sm text-slate-500">{empty}</p>
      )}
    </div>
  );
}

type SummaryBlock = {
  items: string[];
  title: string;
  tone: "cyan" | "amber" | "slate";
};

function splitSentences(value: string) {
  return maskText(value)
    .replace(/\s+/g, " ")
    .trim()
    .split(/(?<=[.!?])\s+(?=[A-Z0-9])/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function timelineItemsFromSummary(value: string) {
  const text = maskText(value).replace(/\s+/g, " ").trim();
  const matches = Array.from(
    text.matchAll(/\b\d+\)\s*([^;]+?)(?=(?:;\s*\d+\)|\.\s|$))/g),
  );

  return matches
    .map((match) => match[1]?.trim())
    .filter((item): item is string => Boolean(item));
}

function summaryBlocks(summary: string): SummaryBlock[] {
  const timelineItems = timelineItemsFromSummary(summary);
  const sentences = splitSentences(summary).filter(
    (sentence) => !/^\d+\)\s/.test(sentence),
  );
  const blocks: SummaryBlock[] = [];
  const activeContext: string[] = [];
  const assessment: string[] = [];
  const caveats: string[] = [];

  for (const sentence of sentences) {
    const lower = sentence.toLowerCase();

    if (
      lower.includes("active") ||
      lower.includes("process") ||
      lower.includes(".exe") ||
      lower.includes("pwsh") ||
      lower.includes("powershell")
    ) {
      activeContext.push(sentence);
    } else if (
      lower.includes("historical") ||
      lower.includes("does not") ||
      lower.includes("not directly") ||
      lower.includes("false positive") ||
      lower.includes("context")
    ) {
      caveats.push(sentence);
    } else {
      assessment.push(sentence);
    }
  }

  if (assessment.length > 0) {
    blocks.push({
      items: assessment.slice(0, 3),
      title: "Assessment",
      tone: "slate",
    });
  }

  if (timelineItems.length > 0) {
    blocks.push({
      items: timelineItems.slice(0, 6),
      title: "Timeline Highlights",
      tone: "cyan",
    });
  }

  if (activeContext.length > 0) {
    blocks.push({
      items: activeContext.slice(0, 4),
      title: "Active Context",
      tone: "amber",
    });
  }

  if (caveats.length > 0) {
    blocks.push({
      items: caveats.slice(0, 4),
      title: "Review Caveats",
      tone: "slate",
    });
  }

  if (blocks.length === 0 && summary.trim() !== "") {
    blocks.push({
      items: [maskText(summary.trim())],
      title: "Moderator Summary",
      tone: "slate",
    });
  }

  return blocks;
}

function SummaryCards({
  playerSummary,
  summary,
}: {
  playerSummary?: string | null;
  summary: string;
}) {
  const blocks = summaryBlocks(summary);
  const toneClass = {
    amber: "border-amber-300/20 bg-amber-400/8",
    cyan: "border-cyan-300/20 bg-cyan-400/8",
    slate: "border-white/10 bg-slate-950/24",
  } satisfies Record<SummaryBlock["tone"], string>;

  return (
    <div className="grid gap-3 xl:grid-cols-2">
      {blocks.map((block) => (
        <div
          className={`rounded-md border p-4 ${toneClass[block.tone]}`}
          key={block.title}
        >
          <h3 className="text-sm font-semibold text-slate-100">
            {block.title}
          </h3>
          <div className="mt-3 space-y-2">
            {block.items.map((item, index) => (
              <p
                className="rounded-md border border-white/8 bg-white/5 px-3 py-2 text-sm leading-6 text-slate-200"
                key={`${block.title}-${index}`}
              >
                {item}
              </p>
            ))}
          </div>
        </div>
      ))}

      {playerSummary ? (
        <div className="rounded-md border border-emerald-300/20 bg-emerald-400/8 p-4 xl:col-span-2">
          <h3 className="text-sm font-semibold text-slate-100">
            Player-safe Summary
          </h3>
          <p className="mt-3 rounded-md border border-white/8 bg-white/5 px-3 py-2 text-sm leading-6 text-slate-300">
            {maskText(playerSummary)}
          </p>
        </div>
      ) : null}
    </div>
  );
}

export function ScanDetailTabs({
  canRetryAiReview,
  scan,
}: ScanDetailTabsProps) {
  const [activeTab, setActiveTab] = useState<TabKey>("overview");
  const [retryStatus, setRetryStatus] = useState<string | null>(null);
  const [selectedProcessRow, setSelectedProcessRow] = useState<JsonRow | null>(
    null,
  );
  const confirm = useConfirm();
  const toast = useToast();
  const result = scan.result;
  const processRows = useMemo(
    () => rowsFrom(result?.processTimeline),
    [result?.processTimeline],
  );
  const processColumns = useMemo<Array<ColumnDef<JsonRow>>>(
    () => [
      column("process", "Process", ["processName", "name", "process"]),
      column("path", "Path", ["path", "executablePath", "pathMasked"]),
      column("parent", "Parent", ["parentProcess", "parent", "parentName"]),
      column("startedAt", "Started", ["startedAt", "startTime", "firstSeenAt"]),
      column("commandLine", "Command", ["commandLine"]),
      column("owner", "Owner", ["owner"]),
      {
        accessorFn: (row) => formatValue(row.sessionId),
        cell: ({ row }) => <TruncatedText value={row.original.sessionId} />,
        header: "Session",
        id: "session",
      },
      {
        accessorFn: (row) => formatValue(row.signatureStatus),
        cell: ({ row }) => <Badge value={row.original.signatureStatus} />,
        header: "Signature",
        id: "signature",
      },
      {
        accessorFn: (row) => networkSummaryText(row.networkSummary),
        cell: ({ row }) => (
          <TruncatedText
            value={networkSummaryText(row.original.networkSummary)}
          />
        ),
        header: "Network",
        id: "network",
      },
      {
        accessorFn: (row) => listSummary(row.suspiciousFlags),
        cell: ({ row }) => (
          <TruncatedText value={listSummary(row.original.suspiciousFlags)} />
        ),
        header: "Flags",
        id: "flags",
      },
      column("status", "Status", ["status", "severity"], "badge"),
      column("source", "Source", ["source", "sourceModule"]),
      {
        cell: ({ row }) => (
          <button
            className="rounded-md border border-white/10 px-3 py-1.5 text-xs font-semibold text-cyan-100 hover:border-cyan-300/40 hover:bg-cyan-300/10"
            onClick={() => setSelectedProcessRow(row.original)}
            type="button"
          >
            Details
          </button>
        ),
        enableSorting: false,
        header: "",
        id: "details",
      },
    ],
    [],
  );
  const exploreRows = useMemo(
    () => rowsFrom(result?.exploreFiles),
    [result?.exploreFiles],
  );
  const utilityRows = useMemo(
    () => rowsFrom(result?.utilities),
    [result?.utilities],
  );
  const windowsRows = useMemo(
    () => rowsFrom(result?.windowsItems),
    [result?.windowsItems],
  );
  const loadedModuleRows = useMemo(
    () => rowsFrom(result?.loadedModules),
    [result?.loadedModules],
  );
  const handleRows = useMemo(
    () => rowsFrom(result?.processHandles),
    [result?.processHandles],
  );
  const persistenceRows = useMemo(
    () => rowsFrom(result?.persistenceItems),
    [result?.persistenceItems],
  );
  const driverRows = useMemo(
    () => rowsFrom(result?.drivers),
    [result?.drivers],
  );
  const eventLogRows = useMemo(() => {
    return [
      ...rowsFrom(result?.eventLogs).map((row) => ({
        forensicSource: "event_log",
        ...row,
      })),
      ...rowsFrom(result?.defenderEvents).map((row) => ({
        forensicSource: "defender",
        ...row,
      })),
    ];
  }, [result?.defenderEvents, result?.eventLogs]);
  const executionArtifactRows = useMemo(
    () => rowsFrom(result?.executionArtifacts),
    [result?.executionArtifacts],
  );
  const fileTriageRows = useMemo(
    () => rowsFrom(result?.fileTriage),
    [result?.fileTriage],
  );
  const networkForensicRows = useMemo(() => {
    return [
      ...rowsFrom(result?.networkConnections).map((row) => ({
        forensicSource: "network_connection",
        ...row,
      })),
      ...rowsFrom(result?.dnsCache).map((row) => ({
        forensicSource: "dns_cache",
        ...row,
      })),
      ...rowsFrom(result?.hostsEntries).map((row) => ({
        forensicSource: "hosts_file",
        ...row,
      })),
    ];
  }, [result?.dnsCache, result?.hostsEntries, result?.networkConnections]);
  const fileTriageColumns = useMemo<Array<ColumnDef<JsonRow>>>(
    () => [
      column("file", "File", ["fileName", "name"]),
      column("extension", "Ext", ["extension"], "badge"),
      column("path", "Path", ["path", "pathMasked"]),
      column("size", "Size", ["size", "sizeBytes"]),
      column("modified", "Modified", ["modifiedTime", "modifiedAt"]),
      column("signature", "Signature", ["signatureStatus"], "badge"),
      column("hash", "Hash", ["hashStatus", "sha256"]),
      column(
        "sourceArtifact",
        "Source Artifact",
        ["sourceArtifact", "source"],
        "badge",
      ),
      {
        accessorFn: (row) => listSummary(row.reasonFlags),
        cell: ({ row }) => (
          <TruncatedText value={listSummary(row.original.reasonFlags)} />
        ),
        header: "Reason Flags",
        id: "reasonFlags",
      },
      column("confidence", "Confidence", ["confidence"]),
      column("status", "Status", ["status", "severity"], "badge"),
    ],
    [],
  );
  const networkForensicColumns = useMemo<Array<ColumnDef<JsonRow>>>(
    () => [
      column("sourceType", "Type", ["forensicSource", "sourceType"], "badge"),
      column("process", "Process", ["processName", "process"]),
      column("pid", "PID", ["pid"]),
      column("local", "Local", ["localAddress", "localEndpoint"]),
      column("remote", "Remote / Domain", ["remoteAddress", "domain", "host"]),
      column("state", "State", ["state", "protocol"], "badge"),
      column("source", "Source", ["source"]),
      {
        accessorFn: (row) => listSummary(row.reasonFlags),
        cell: ({ row }) => (
          <TruncatedText value={listSummary(row.original.reasonFlags)} />
        ),
        header: "Reason Flags",
        id: "reasonFlags",
      },
      column("confidence", "Confidence", ["confidence"]),
      column("status", "Status", ["status", "severity"], "badge"),
    ],
    [],
  );
  const networkBreakdown = useMemo(
    () => ({
      active: rowsFrom(result?.networkConnections).length,
      dns: rowsFrom(result?.dnsCache).length,
      hosts: rowsFrom(result?.hostsEntries).length,
    }),
    [result?.dnsCache, result?.hostsEntries, result?.networkConnections],
  );
  const forensicTimelineRows = useMemo(
    () => rowsFrom(result?.forensicTimeline),
    [result?.forensicTimeline],
  );
  const forensicTimelineColumns = useMemo<Array<ColumnDef<JsonRow>>>(
    () => [
      column("time", "Time", ["timestamp", "createdAt", "startedAt"]),
      column("severity", "Severity", ["severity"], "badge"),
      column("source", "Source", ["sourceModule", "source"], "badge"),
      column("eventType", "Event Type", [
        "eventType",
        "action",
        "artifactType",
      ]),
      column("subject", "Subject", ["subject", "title", "name"]),
      column("processPath", "Process / Path", ["processName", "path"]),
      column("confidence", "Confidence", ["confidence"]),
      {
        accessorFn: (row) => listSummary(row.reasonFlags),
        cell: ({ row }) => (
          <TruncatedText value={listSummary(row.original.reasonFlags)} />
        ),
        header: "Reason Flags",
        id: "reasonFlags",
      },
      {
        accessorFn: (row) => listSummary(row.evidenceRefs),
        cell: ({ row }) => (
          <TruncatedText value={listSummary(row.original.evidenceRefs)} />
        ),
        header: "Evidence",
        id: "evidenceRefs",
      },
      column("correlation", "Correlation", ["correlationId"], "badge"),
    ],
    [],
  );
  const forensicTimelineSummary = objectFrom(result?.integrity?.af7Summary);
  const scannerAuditRows = useMemo(
    () => rowsFrom(result?.auditLog),
    [result?.auditLog],
  );
  const auditRows = [
    ...scannerAuditRows.map((row) => ({ source: "scanner", ...row })),
    ...scan.auditLogs.map((entry) => ({
      source: "dashboard",
      action: entry.action,
      entityType: entry.entityType,
      entityId: entry.entityId,
      timestamp: entry.createdAt,
    })),
  ];
  const evidenceRows = scan.evidence.map((item) => ({
    id: item.id,
    clientEvidenceId: item.clientEvidenceId,
    type: item.type,
    title: item.title,
    data: item.data,
    storageRef: item.storageRef,
    createdAt: item.createdAt,
  }));
  const launcherProfileRows: JsonRow[] = scan.launcherProfiles.map(
    (profile) => ({
      ...profile,
      tags: profile.tags,
    }),
  );
  const clientModRows: JsonRow[] = scan.clientModAssets.map((asset) => ({
    ...asset,
    totalSize: asset.totalSize ? `${asset.totalSize} bytes` : null,
  }));
  const processTimeRows: JsonRow[] = scan.processTimes.map((processTime) => ({
    ...processTime,
  }));
  const fileLogRows: JsonRow[] = scan.fileLogs.map((fileLog) => ({
    ...fileLog,
  }));
  const robloxUtilityRows = utilityRows.filter((row) =>
    ["scope", "module", "sourceModule", "category"].some((key) =>
      formatValue(row[key]).toLowerCase().includes("roblox"),
    ),
  );
  const robloxWindowsRows = windowsRows.filter((row) =>
    ["scope", "module", "sourceModule", "category"].some((key) =>
      formatValue(row[key]).toLowerCase().includes("roblox"),
    ),
  );
  const robloxFindings = scan.findings.filter(isRobloxFinding);
  const latestAutomationEvent = scan.automationEvents[0];
  const aiReview = scan.aiReview;
  const keyIndicators = listFrom(aiReview?.keyIndicators);
  const possibleFalsePositives = listFrom(aiReview?.possibleFalsePositives);
  const contradictions = listFrom(aiReview?.contradictions);
  const moderatorChecklist = listFrom(aiReview?.moderatorChecklist);
  const questionsForPlayer = listFrom(aiReview?.questionsForPlayer);

  const overview = result?.overview ?? {};
  const systemIdentity = result?.systemIdentity ?? {};
  const networkSnapshot = result?.networkSnapshot ?? {};
  const integrity = result?.integrity ?? {};
  const sectionUploadRows: JsonRow[] = Object.entries(
    objectFrom(integrity.sectionUploadStatus),
  ).map(([section, value]) => ({
    section,
    ...objectFrom(value),
  }));
  const moduleRows: JsonRow[] = scan.modules.map((module) => ({
    ...module,
    displayStatus: displayModuleStatus(module),
    limitedArtifact:
      module.errorCode === "MODULE_WARNING" ? "Limited artifact" : null,
  }));
  const bootTime =
    overview.bootTime ??
    overview.computerStartedAt ??
    overview.systemBootTime ??
    overview.uptimeStartedAt ??
    systemIdentity.bootTime ??
    systemIdentity.computerStartedAt ??
    systemIdentity.systemBootTime ??
    systemIdentity.uptimeStartedAt;
  const overviewRows: Array<{
    icon: LucideIcon;
    label: string;
    value: unknown;
    variant?: "text" | "boolean" | "country";
  }> = [
    { icon: Hash, label: "ID", value: scan.id },
    {
      icon: Monitor,
      label: "Operating System",
      value: systemIdentity.os ?? overview.os,
    },
    { icon: MonitorCog, label: "VM", value: overview.vm, variant: "boolean" },
    {
      icon: Network,
      label: "Connection Type",
      value: networkSnapshot.connectionType ?? overview.connectionType,
    },
    {
      icon: Flag,
      label: "Country",
      value: networkSnapshot.country ?? overview.country,
      variant: "country",
    },
    {
      icon: Fingerprint,
      label: "Device",
      value: scan.device?.fingerprintPrefix,
    },
    {
      icon: ShieldAlert,
      label: "HWID Mark",
      value: scan.device?.currentMark?.status ?? "None",
    },
    {
      icon: Power,
      label: "Installation",
      value: overview.installationDate ?? systemIdentity.installationDate,
    },
    {
      icon: Trash2,
      label: "Recycle Bin",
      value:
        overview.recycleBinLastActivity ?? integrity.recycleBinLastActivity,
    },
    { icon: Clock3, label: "Computer Started", value: bootTime },
    {
      icon: Gauge,
      label: "Scan Duration",
      value: scanDuration(scan, overview),
    },
    {
      icon: CalendarClock,
      label: "Date",
      value: scan.startedAt ?? scan.createdAt,
    },
  ];

  async function handleRetryAiReview() {
    const ok = await confirm({
      confirmLabel: "Retry AI review",
      description:
        "This will queue the scan.completed event for n8n again. It will not perform any automatic ban.",
      title: "Retry AI review?",
    });

    if (!ok) {
      return;
    }

    setRetryStatus("Retrying AI review...");

    try {
      await retryAiReview(scan.id);
      setRetryStatus("AI review event queued. Refresh shortly to see updates.");
      toast.success("AI review event queued. Refresh shortly to see updates.");
    } catch {
      setRetryStatus("Could not retry AI review.");
      toast.error("Could not retry AI review.");
    }
  }

  return (
    <div className="mt-6 space-y-6">
      <div className="flex gap-2 overflow-x-auto rounded-lg border border-white/10 bg-slate-950/25 p-2">
        {tabs.map((tab) => (
          <button
            className={`h-10 shrink-0 rounded-md px-3 text-sm font-semibold transition ${
              activeTab === tab.key
                ? "bg-cyan-500 text-slate-950"
                : "text-slate-300 hover:bg-white/8 hover:text-slate-100"
            }`}
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            type="button"
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === "overview" ? (
        <section className="space-y-4">
          <div className="grid gap-4 xl:grid-cols-[minmax(18rem,0.92fr)_minmax(18rem,0.92fr)_minmax(24rem,1.9fr)]">
            <ScanInformationPanel rows={overviewRows} />
            <IndicationGraph scan={scan} />
            <OverviewIndicationLog
              onOpenEvidence={() => setActiveTab("evidence")}
              onOpenFullLog={() => setActiveTab("indications")}
              scan={scan}
            />
          </div>
          <div className="rounded-lg border border-white/10 bg-[#172842] p-4">
            <SectionHeader
              description="Shows which scanner modules ran, how long they took, and whether a module returned an error."
              icon={ListChecks}
              title="Module Status"
            />
            <DataTable
              columns={[
                column("moduleName", "Module", ["moduleName"]),
                column("status", "Status", ["displayStatus"], "badge"),
                column("durationMs", "Duration ms", ["durationMs"]),
                column(
                  "limitedArtifact",
                  "Artifact Limit",
                  ["limitedArtifact"],
                  "badge",
                ),
                column("errorMessage", "Error Message", ["errorMessage"]),
              ]}
              data={moduleRows}
              emptyMessage="No module status was uploaded for this scan."
              searchPlaceholder="Search modules..."
            />
          </div>
          {sectionUploadRows.length > 0 ? (
            <div className="rounded-lg border border-white/10 bg-[#172842] p-4">
              <SectionHeader
                description="Chunked upload status for large forensic sections. Failed sections mean the core scan is saved, but that section needs a retry or rescan."
                icon={Database}
                title="Section Upload Status"
              />
              <DataTable
                columns={[
                  column("section", "Section", ["section"]),
                  column("status", "Status", ["status"], "badge"),
                  column("chunks", "Chunks", ["chunkCount", "chunkIndex"]),
                  column("items", "Items", ["uploadedItems", "totalItems"]),
                  column("errorCode", "Error", ["errorCode"]),
                  column("uploadedAt", "Updated", ["uploadedAt"]),
                ]}
                data={sectionUploadRows}
                emptyMessage="No section upload status is available."
                searchPlaceholder="Search section status..."
              />
            </div>
          ) : null}
        </section>
      ) : null}

      {activeTab === "aiReview" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <SectionHeader
              description="AI-assisted review from n8n. This is advisory only and never performs automatic bans."
              icon={Bot}
              title="AI Review"
            />
            {canRetryAiReview ? (
              <button
                className="inline-flex h-9 items-center gap-2 rounded-md border border-cyan-300/30 bg-cyan-400/10 px-3 text-xs font-semibold text-cyan-100 transition hover:bg-cyan-400/16"
                onClick={handleRetryAiReview}
                type="button"
              >
                <Sparkles className="h-4 w-4" />
                Retry Review
              </button>
            ) : null}
          </div>

          <div className="grid gap-3 lg:grid-cols-4">
            <div className="rounded-md border border-white/10 bg-slate-950/24 p-4">
              <p className="text-xs uppercase text-slate-400">Review Status</p>
              <div className="mt-2">
                <Badge value={scan.reviewStatus} />
              </div>
            </div>
            <div className="rounded-md border border-white/10 bg-slate-950/24 p-4">
              <p className="text-xs uppercase text-slate-400">n8n Status</p>
              <div className="mt-2">
                <Badge value={latestAutomationEvent?.status ?? "Not queued"} />
              </div>
            </div>
            <div className="rounded-md border border-white/10 bg-slate-950/24 p-4">
              <p className="text-xs uppercase text-slate-400">Attempts</p>
              <p className="mt-2 text-lg font-semibold text-slate-100">
                {latestAutomationEvent?.attemptCount ?? 0}
              </p>
            </div>
            <div className="rounded-md border border-white/10 bg-slate-950/24 p-4">
              <p className="text-xs uppercase text-slate-400">Generated</p>
              <p className="mt-2 text-sm font-semibold text-slate-100">
                {formatValue(aiReview?.generatedAt)}
              </p>
            </div>
          </div>

          {latestAutomationEvent?.lastError ? (
            <div className="mt-4 rounded-md border border-rose-300/25 bg-rose-400/10 p-3 text-sm text-rose-100">
              {latestAutomationEvent.lastError}
            </div>
          ) : null}

          {retryStatus ? (
            <div className="mt-4 rounded-md border border-cyan-300/20 bg-cyan-400/10 p-3 text-sm text-cyan-100">
              {retryStatus}
            </div>
          ) : null}

          {aiReview ? (
            <div className="mt-4 space-y-4">
              <div className="grid gap-3 lg:grid-cols-[1fr_1fr_1fr]">
                <div className="rounded-md border border-white/10 bg-slate-950/24 p-4">
                  <p className="text-xs uppercase text-slate-400">Assessment</p>
                  <p className="mt-2 text-lg font-semibold text-slate-100">
                    {aiReview.assessment}
                  </p>
                </div>
                <div className="rounded-md border border-white/10 bg-slate-950/24 p-4">
                  <p className="text-xs uppercase text-slate-400">Confidence</p>
                  <p className="mt-2 text-lg font-semibold text-slate-100">
                    {aiReview.confidence}%
                  </p>
                </div>
                <div className="rounded-md border border-white/10 bg-slate-950/24 p-4">
                  <p className="text-xs uppercase text-slate-400">
                    Recommended Action
                  </p>
                  <p className="mt-2 text-lg font-semibold text-slate-100">
                    {recommendedActionLabel(aiReview.recommendedAction)}
                  </p>
                </div>
              </div>

              <SummaryCards
                playerSummary={aiReview.summaryForPlayer}
                summary={aiReview.summaryForModerator}
              />

              <div className="grid gap-3 xl:grid-cols-2">
                <ReviewList
                  empty="No key indicators were provided."
                  items={keyIndicators}
                  title="Key Indicators"
                />
                <ReviewList
                  empty="No possible false positives were provided."
                  items={possibleFalsePositives}
                  title="Possible False Positives"
                />
                <ReviewList
                  empty="No contradictions were provided."
                  items={contradictions}
                  title="Contradictions"
                />
                <ReviewList
                  empty="No player questions were provided."
                  items={questionsForPlayer}
                  title="Questions for Player"
                />
              </div>

              <ReviewList
                empty="No moderator checklist was provided."
                items={moderatorChecklist}
                title="Moderator Checklist"
              />

              <div className="rounded-md border border-white/10 bg-slate-950/24 p-4">
                <h3 className="text-sm font-semibold text-slate-100">
                  Evidence References
                </h3>
                {aiReview.evidenceLinks.length > 0 ? (
                  <div className="mt-3 flex flex-wrap gap-2">
                    {aiReview.evidenceLinks.map((link) => (
                      <button
                        className="rounded-md border border-cyan-300/30 bg-cyan-400/10 px-2 py-1 text-xs font-semibold text-cyan-100 transition hover:bg-cyan-400/16"
                        key={link.id}
                        onClick={() =>
                          setActiveTab(
                            link.evidence ? "evidence" : "indications",
                          )
                        }
                        type="button"
                      >
                        {link.evidence?.title ??
                          link.finding?.title ??
                          "Evidence reference"}
                      </button>
                    ))}
                  </div>
                ) : (
                  <p className="mt-3 text-sm text-slate-500">
                    No linked evidence references were stored.
                  </p>
                )}
              </div>

              <div className="grid gap-3 text-sm text-slate-300 lg:grid-cols-3">
                <div className="rounded-md border border-white/10 bg-white/5 p-3">
                  Model: {aiReview.model ?? "Unknown"}
                </div>
                <div className="rounded-md border border-white/10 bg-white/5 p-3">
                  Prompt: {aiReview.promptVersion ?? "Unknown"}
                </div>
                <div className="rounded-md border border-white/10 bg-white/5 p-3">
                  Input hash: {aiReview.inputHash ?? "Unknown"}
                </div>
              </div>
            </div>
          ) : (
            <div className="mt-4 rounded-md border border-white/10 bg-slate-950/24 p-6 text-sm text-slate-300">
              No AI review has been stored for this scan yet.
            </div>
          )}
        </section>
      ) : null}

      {activeTab === "device" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <SectionHeader
            description="Safe device fingerprint metadata and active HWID mark for this scan. Raw hardware identifiers are never shown."
            icon={Fingerprint}
            title="Device / HWID"
          />
          {scan.device ? (
            <div className="space-y-4">
              <div className="grid gap-3 lg:grid-cols-4">
                <div className="rounded-md border border-white/10 bg-slate-950/24 p-4">
                  <p className="text-xs uppercase text-slate-400">
                    Fingerprint Prefix
                  </p>
                  <p className="mt-2 font-mono text-lg font-semibold text-cyan-100">
                    {scan.device.fingerprintPrefix}
                  </p>
                </div>
                <div className="rounded-md border border-white/10 bg-slate-950/24 p-4">
                  <p className="text-xs uppercase text-slate-400">Version</p>
                  <p className="mt-2 text-lg font-semibold text-slate-100">
                    {scan.device.fingerprintVersion}
                  </p>
                </div>
                <div className="rounded-md border border-white/10 bg-slate-950/24 p-4">
                  <p className="text-xs uppercase text-slate-400">Confidence</p>
                  <p className="mt-2 text-lg font-semibold text-slate-100">
                    {scan.device.fingerprintConfidence}
                  </p>
                </div>
                <div className="rounded-md border border-white/10 bg-slate-950/24 p-4">
                  <p className="text-xs uppercase text-slate-400">Scans</p>
                  <p className="mt-2 text-lg font-semibold text-slate-100">
                    {scan.device.scanCount}
                  </p>
                </div>
              </div>

              <div className="rounded-md border border-white/10 bg-slate-950/24 p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 className="text-base font-semibold text-slate-100">
                      Current mark
                    </h3>
                    <p className="mt-1 text-sm text-slate-400">
                      Active global/account HWID mark matched for this scan.
                    </p>
                  </div>
                  <Badge value={scan.device.currentMark?.status ?? "None"} />
                </div>
                {scan.device.currentMark ? (
                  <div className="mt-4 rounded-md border border-white/10 bg-white/5 p-3 text-sm text-slate-200">
                    <p>{scan.device.currentMark.reason}</p>
                    <p className="mt-2 text-xs text-slate-400">
                      {scan.device.currentMark.scope}
                      {scan.device.currentMark.accountName
                        ? ` - ${scan.device.currentMark.accountName}`
                        : ""}{" "}
                      marked at{" "}
                      {formatMaybeJakartaDateTime(
                        scan.device.currentMark.markedAt,
                      )}
                    </p>
                  </div>
                ) : null}
              </div>

              <Link
                className="inline-flex h-10 items-center rounded-md bg-cyan-500 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300"
                href={`/devices/${scan.device.id}`}
              >
                Open device detail
              </Link>
            </div>
          ) : (
            <div className="rounded-md border border-white/10 bg-slate-950/24 p-6 text-sm text-slate-300">
              No device fingerprint was uploaded for this scan.
            </div>
          )}
        </section>
      ) : null}

      {activeTab === "launcherProfiles" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <SectionHeader
            description="Roblox launchers and bootstrapper profiles found by the main scanner. Bloxstrap is not automatically severe."
            icon={Rocket}
            title="Launcher Profiles"
          />
          <DataTable
            columns={[
              column("profileName", "Profile", ["profileName"]),
              column(
                "launcherType",
                "Launcher Type",
                ["launcherType"],
                "badge",
              ),
              column("version", "Version", ["version", "channel"]),
              column("path", "Path", ["pathMasked", "path"]),
              column("publisher", "Publisher", ["publisher"]),
              column("status", "Status", ["status"], "badge"),
              column("tags", "Tags", ["tags"]),
              column("lastLaunchTime", "Last Launch", [
                "lastLaunchTime",
                "updateTime",
                "installTime",
              ]),
            ]}
            data={launcherProfileRows}
            emptyMessage="No Roblox launcher profiles were uploaded."
            searchPlaceholder="Search launcher profiles..."
          />
        </section>
      ) : null}

      {activeTab === "clientMods" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <SectionHeader
            description="Roblox or Bloxstrap client assets and mods. Custom assets are review signals, not automatic cheat proof."
            icon={PackageOpen}
            title="Client Mods / Assets"
          />
          <DataTable
            columns={[
              column("name", "Name", ["name"]),
              column("sourceLauncher", "Source Launcher", ["sourceLauncher"]),
              column("path", "Path", ["pathMasked", "path"]),
              column("fileCount", "Files", ["fileCount"]),
              column("totalSize", "Total Size", ["totalSize"]),
              column("createdTime", "Created", ["createdTime"]),
              column("modifiedTime", "Modified", ["modifiedTime"]),
              column("status", "Status", ["status"], "badge"),
              column("metadata", "Metadata", ["metadata"]),
            ]}
            data={clientModRows}
            emptyMessage="No Roblox client mods or assets were uploaded."
            searchPlaceholder="Search client mods/assets..."
          />
        </section>
      ) : null}

      {activeTab === "process" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <SectionHeader
            description="Processes observed by the scanner with parent, command line redaction, owner/session, signature, network summary, and suspicious path flags when available."
            icon={TerminalSquare}
            title="Process Timeline"
          />
          <DataTable
            columns={processColumns}
            data={processRows}
            emptyMessage="No process timeline rows were uploaded."
            searchPlaceholder="Search process timeline..."
          />
          {selectedProcessRow ? (
            <ProcessDetailPanel
              onClose={() => setSelectedProcessRow(null)}
              row={selectedProcessRow}
            />
          ) : null}
        </section>
      ) : null}

      {activeTab === "processTimes" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <SectionHeader
            description="Roblox-relevant process timing evidence from live process, event artifact, compatibility metadata, or scan observation sources."
            icon={Clock3}
            title="Process Times"
          />
          <DataTable
            columns={[
              column("processName", "Process", ["processName"]),
              column("path", "Path", ["pathMasked", "path"]),
              column("firstSeenAt", "First Seen", ["firstSeenAt"]),
              column("lastSeenAt", "Last Seen", ["lastSeenAt"]),
              column("startedAt", "Started", ["startedAt"]),
              column("endedAt", "Ended", ["endedAt"]),
              column("durationMs", "Duration ms", ["durationMs"]),
              column("source", "Source", ["source"]),
              column("status", "Status", ["status"], "badge"),
            ]}
            data={processTimeRows}
            emptyMessage="No Roblox process time records were uploaded."
            searchPlaceholder="Search process times..."
          />
        </section>
      ) : null}

      {activeTab === "explore" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <SectionHeader
            description="File metadata and file activity found inside approved scanner scope."
            icon={FolderSearch}
            title="Explore Files"
          />
          <DataTable
            columns={[
              column("action", "Action", ["action", "eventType"], "badge"),
              column("path", "Path", [
                "path",
                "pathMasked",
                "newPath",
                "newPathMasked",
              ]),
              column("oldPath", "Old Path", ["oldPath", "oldPathMasked"]),
              column("timestamp", "Timestamp", [
                "timestamp",
                "createdAt",
                "modifiedAt",
              ]),
              column("source", "Source", ["source", "sourceModule"]),
              column("confidence", "Confidence", ["confidence"]),
              column("severity", "Severity", ["severity", "status"], "badge"),
            ]}
            data={exploreRows}
            emptyMessage="No explored file metadata was uploaded."
            searchPlaceholder="Search file paths..."
          />
        </section>
      ) : null}

      {activeTab === "fileLogs" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <SectionHeader
            description="Chronological Roblox file/program activity from approved artifact sources. Rename and move rows show both old and new paths."
            icon={History}
            title="Explore File Logs"
          />
          <DataTable
            columns={[
              column("action", "Action", ["action"], "fileAction"),
              column("path", "Path", ["pathMasked", "path"]),
              column("oldPath", "Old Path", ["oldPathMasked", "oldPath"]),
              column("newPath", "New Path", ["newPathMasked", "newPath"]),
              column("timestamp", "Timestamp", ["timestamp", "createdAt"]),
              column("source", "Source", ["source"]),
              column("confidence", "Confidence", ["confidence"]),
              column("relatedProcess", "Related Process", ["relatedProcess"]),
              column("severity", "Severity", ["severity"], "badge"),
            ]}
            data={fileLogRows}
            emptyMessage="No Roblox file log rows were uploaded."
            searchPlaceholder="Search file logs..."
          />
        </section>
      ) : null}

      {activeTab === "utilities" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <SectionHeader
            description={`Utilities such as debuggers, injectors, macro tools, overlays, or remote-control tools. Roblox-tagged rows: ${robloxUtilityRows.length}.`}
            icon={Boxes}
            title="Utilities"
          />
          <DataTable
            columns={[
              column("name", "Name", ["name", "processName", "utilityName"]),
              column("category", "Category", ["category", "type"]),
              column("path", "Path", ["path", "pathMasked"]),
              column("status", "Status", ["status", "severity"], "badge"),
              column("source", "Source", ["source", "sourceModule"]),
              column("lastSeenAt", "Last Seen", ["lastSeenAt", "timestamp"]),
            ]}
            data={utilityRows}
            emptyMessage="No utility rows were uploaded."
            searchPlaceholder="Search utilities..."
          />
        </section>
      ) : null}

      {activeTab === "windows" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <SectionHeader
            description={`Windows services, drivers, startup entries, tasks, registry items, or installed-program metadata. Roblox-tagged rows: ${robloxWindowsRows.length}.`}
            icon={MonitorCog}
            title="Windows Items"
          />
          <DataTable
            columns={[
              column("type", "Type", ["itemType", "type", "category"]),
              column("name", "Name", ["name", "displayName", "serviceName"]),
              column("path", "Path", ["path", "pathMasked", "imagePath"]),
              column("status", "Status", ["status", "severity"], "badge"),
              column("source", "Source", ["source", "sourceModule"]),
              column("timestamp", "Timestamp", [
                "timestamp",
                "createdAt",
                "modifiedAt",
              ]),
            ]}
            data={windowsRows}
            emptyMessage="No Windows item rows were uploaded."
            searchPlaceholder="Search Windows items..."
          />
        </section>
      ) : null}

      {activeTab === "loadedModules" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <SectionHeader
            description="DLL/module metadata loaded inside Roblox or configured game target processes. Manual-mapped DLLs may not appear in normal module lists."
            icon={Puzzle}
            title="Loaded DLLs"
          />
          <DataTable
            columns={[
              column("targetProcessName", "Target", ["targetProcessName"]),
              column("moduleName", "DLL", ["moduleName", "name"]),
              column("path", "Path", ["pathMasked", "path"]),
              column("publisher", "Publisher", ["publisher", "signer"]),
              column(
                "signatureStatus",
                "Signature",
                ["signatureStatus"],
                "badge",
              ),
              column("hashStatus", "Hash", ["hashStatus", "sha256"]),
              column("modifiedTime", "Modified", [
                "modifiedTime",
                "createdTime",
              ]),
              column("flags", "Flags", ["suspiciousFlags"]),
              column("confidence", "Confidence", ["confidence"]),
              column("status", "Status", ["status", "severity"], "badge"),
            ]}
            data={loadedModuleRows}
            emptyMessage="No loaded DLL forensic data was uploaded for this scan yet."
            searchPlaceholder="Search loaded DLLs..."
          />
        </section>
      ) : null}

      {activeTab === "handles" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <SectionHeader
            description="External processes holding process handles to Roblox or configured game targets. This is metadata-only and does not read process memory."
            icon={Network}
            title="Handles"
          />
          <DataTable
            columns={[
              column("targetProcessName", "Target", ["targetProcessName"]),
              column("sourceProcessName", "Source Process", [
                "sourceProcessName",
                "processName",
              ]),
              column("sourcePath", "Source Path", ["sourcePath", "path"]),
              column("accessRights", "Access Rights", ["accessRights"]),
              column("accessMask", "Mask", ["accessMask"]),
              column("publisher", "Publisher", ["publisher", "signer"]),
              column(
                "signatureStatus",
                "Signature",
                ["signatureStatus"],
                "badge",
              ),
              column("flags", "Flags", ["suspiciousFlags"]),
              column("confidence", "Confidence", ["confidence"]),
              column("status", "Status", ["status", "severity"], "badge"),
            ]}
            data={handleRows}
            emptyMessage="No process handle forensic data was uploaded for this scan yet."
            searchPlaceholder="Search process handles..."
          />
        </section>
      ) : null}

      {activeTab === "persistence" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
            <SectionHeader
              description="Startup, autoruns, scheduled task, and registry persistence metadata from scoped forensic collectors."
              icon={Power}
              title="Persistence"
            />
            <ForensicModeBadge integrity={result?.integrity} />
          </div>
          <DataTable
            columns={[
              column(
                "type",
                "Type",
                ["kind", "type", "persistenceType"],
                "badge",
              ),
              column("name", "Name", ["name", "displayName"]),
              column("command", "Command / Path", [
                "command",
                "path",
                "imagePath",
              ]),
              column("location", "Hive / Location", ["location", "sourceHive"]),
              column("signature", "Signature", ["signatureStatus"], "badge"),
              column("publisher", "Publisher", ["publisher", "signer"]),
              column("missingFile", "Missing", ["missingFile"], "badge"),
              column("flags", "Flags", ["suspiciousFlags"]),
              column("confidence", "Confidence", ["confidence"]),
              column("status", "Status", ["status", "severity"], "badge"),
            ]}
            data={persistenceRows}
            emptyMessage="No persistence forensic data was uploaded for this scan yet."
            searchPlaceholder="Search persistence..."
          />
        </section>
      ) : null}

      {activeTab === "drivers" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
            <SectionHeader
              description="Kernel driver and driver registry metadata. Unsigned or user-writable paths require manual review."
              icon={MonitorCog}
              title="Drivers"
            />
            <ForensicModeBadge integrity={result?.integrity} />
          </div>
          <DataTable
            columns={[
              column("driver", "Driver", ["name", "driverName", "displayName"]),
              column("path", "Image Path", ["path", "imagePath"]),
              column("state", "State", ["state", "loadedState"], "badge"),
              column("startMode", "Start Mode", ["startMode"]),
              column("signature", "Signature", ["signatureStatus"], "badge"),
              column("publisher", "Publisher", ["publisher", "signer"]),
              column(
                "outsideSystem32",
                "Outside System32",
                ["outsideSystem32Drivers"],
                "badge",
              ),
              column("modified", "Modified", ["modifiedTime", "createdTime"]),
              column("flags", "Flags", ["suspiciousFlags"]),
              column("confidence", "Confidence", ["confidence"]),
              column("status", "Status", ["status", "severity"], "badge"),
            ]}
            data={driverRows}
            emptyMessage="No driver forensic data was uploaded for this scan yet."
            searchPlaceholder="Search drivers..."
          />
        </section>
      ) : null}

      {activeTab === "eventLogs" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
            <SectionHeader
              description="Selected Windows and Defender events such as service installs, task creation, log cleared, Defender detections, and exclusions."
              icon={Database}
              title="Event Logs"
            />
            <div className="flex flex-wrap gap-2">
              <Badge
                value={`Windows Events: ${rowsFrom(result?.eventLogs).length}`}
              />
              <Badge
                value={`Defender: ${rowsFrom(result?.defenderEvents).length}`}
              />
              <ForensicModeBadge
                integrity={result?.integrity}
                summaryKey="af4Summary"
              />
            </div>
          </div>
          <DataTable
            columns={[
              column(
                "sourceType",
                "Source Type",
                ["forensicSource", "eventType"],
                "badge",
              ),
              column("timestamp", "Timestamp", ["timestamp", "createdAt"]),
              column("eventId", "Event ID", ["eventId"]),
              column("title", "Title", ["title", "name", "event"]),
              column("channel", "Channel / Provider", [
                "channel",
                "provider",
                "source",
              ]),
              column("subject", "Subject / Process", [
                "processName",
                "parentProcess",
                "threatName",
                "name",
                "value",
              ]),
              column("path", "Path / Command", ["path", "command"]),
              column("flags", "Flags", ["suspiciousFlags"]),
              column("confidence", "Confidence", ["confidence"]),
              column("status", "Status", ["status", "severity"], "badge"),
            ]}
            data={eventLogRows}
            emptyMessage="No event log or Defender forensic data was uploaded for this scan yet."
            searchPlaceholder="Search event logs and Defender..."
          />
        </section>
      ) : null}

      {activeTab === "executionArtifacts" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
            <SectionHeader
              description="Execution artifact metadata such as Prefetch, Amcache, ShimCache, Recent Files, Jump Lists, Recycle Bin, scoped folders, and redacted PowerShell history."
              icon={History}
              title="Execution Artifacts"
            />
            <ForensicModeBadge
              integrity={result?.integrity}
              summaryKey="af5Summary"
            />
          </div>
          <DataTable
            columns={[
              column(
                "artifactType",
                "Artifact",
                ["artifactType", "type", "kind"],
                "badge",
              ),
              column("action", "Action", ["action", "eventType"], "badge"),
              column("name", "Name", ["name", "processName", "fileName"]),
              column("path", "Path / Command", ["path", "command"]),
              column("timestamp", "Timestamp", [
                "timestamp",
                "modifiedTime",
                "createdAt",
              ]),
              column("source", "Source", ["source"]),
              column("confidence", "Confidence", ["confidence"]),
              column("flags", "Flags", ["suspiciousFlags"]),
              column("status", "Status", ["status", "severity"], "badge"),
            ]}
            data={executionArtifactRows}
            emptyMessage="No execution artifact forensic data was uploaded for this scan yet."
            searchPlaceholder="Search execution artifacts..."
          />
        </section>
      ) : null}

      {activeTab === "fileTriage" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <SectionHeader
              description="Suspicious file candidates selected from scoped artifacts. Hash and ADS checks only run for review candidates."
              icon={FileSearch}
              title="File Triage"
            />
            <ForensicModeBadge
              integrity={result?.integrity}
              summaryKey="af6Summary"
            />
          </div>
          <DataTable
            columns={fileTriageColumns}
            data={fileTriageRows}
            emptyMessage="No file triage forensic data was uploaded for this scan yet."
            searchPlaceholder="Search file triage..."
          />
        </section>
      ) : null}

      {activeTab === "networkForensics" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <SectionHeader
              description="Active connection, relevant DNS cache, and hosts file metadata. DNS and USB-style context are low-confidence signals."
              icon={Network}
              title="Network"
            />
            <div className="flex flex-wrap items-center gap-2">
              <Badge value={`Active ${networkBreakdown.active}`} />
              <Badge value={`DNS ${networkBreakdown.dns}`} />
              <Badge value={`Hosts ${networkBreakdown.hosts}`} />
              <ForensicModeBadge
                integrity={result?.integrity}
                summaryKey="af6Summary"
              />
            </div>
          </div>
          <DataTable
            columns={networkForensicColumns}
            data={networkForensicRows}
            emptyMessage="No network forensic data was uploaded for this scan yet."
            searchPlaceholder="Search network context..."
          />
        </section>
      ) : null}

      {activeTab === "forensicTimeline" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <SectionHeader
              description="Merged chronology from forensic modules with correlation references. Search by source, severity, confidence, or time."
              icon={CalendarClock}
              title="Forensic Timeline"
            />
            <div className="flex flex-wrap items-center gap-2">
              <Badge
                value={`${formatValue(forensicTimelineSummary.timelineRows)} rows`}
              />
              <Badge
                value={`${formatValue(forensicTimelineSummary.correlationFindings)} correlations`}
              />
              <ForensicModeBadge
                integrity={result?.integrity}
                summaryKey="af7Summary"
              />
              <ForensicTuningBadges integrity={result?.integrity} />
            </div>
          </div>
          <p className="mt-3 text-xs text-slate-400">
            Historical artifact timestamps show when Windows recorded an
            artifact, not proof that it was active during this scan.
          </p>
          <DataTable
            columns={forensicTimelineColumns}
            data={forensicTimelineRows}
            emptyMessage="No forensic timeline rows were uploaded for this scan yet."
            searchPlaceholder="Search timeline by time, source, severity, confidence..."
          />
        </section>
      ) : null}

      {activeTab === "evidence" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <SectionHeader
            description="Evidence records referenced by findings. Sensitive values are redacted or masked."
            icon={FileSearch}
            title="Evidence"
          />
          <DataTable
            columns={[
              column("id", "Evidence ID", ["clientEvidenceId", "id"]),
              column("type", "Type", ["type"], "badge"),
              column("title", "Title", ["title"]),
              column("data", "Data", ["data"]),
              column("storageRef", "Storage Ref", ["storageRef"]),
              column("createdAt", "Created", ["createdAt"]),
            ]}
            data={evidenceRows}
            emptyMessage="No evidence references were uploaded."
            searchPlaceholder="Search evidence..."
          />
        </section>
      ) : null}

      {activeTab === "audit" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <SectionHeader
            description="Scanner-side audit rows plus dashboard audit entries tied to this scan."
            icon={ClipboardList}
            title="Audit Log"
          />
          <DataTable
            columns={[
              column("source", "Source", ["source"], "badge"),
              column("action", "Action", ["action", "event", "eventType"]),
              column("entity", "Entity", ["entityType", "entityId"]),
              column("path", "Path", ["path", "pathMasked"]),
              column("status", "Status", ["status", "severity"], "badge"),
              column("timestamp", "Timestamp", ["timestamp", "createdAt"]),
            ]}
            data={auditRows}
            emptyMessage="No audit rows are available for this scan."
            searchPlaceholder="Search audit log..."
          />
        </section>
      ) : null}

      {activeTab === "indications" ? (
        <section className="rounded-lg border border-white/10 bg-[#172842] p-4">
          <SectionHeader
            description="All indications produced by scanner modules or rules, with evidence references where available."
            icon={ShieldAlert}
            title="Indication Log"
          />
          <div className="mb-4 rounded-lg border border-cyan-300/20 bg-cyan-400/8 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-semibold text-cyan-100">
                  Roblox-specific indications
                </h3>
                <p className="mt-1 text-xs text-slate-400">
                  Findings from Roblox module categories or source modules.
                </p>
              </div>
              <span className="rounded-md border border-cyan-300/30 bg-cyan-400/10 px-2 py-1 text-xs font-semibold text-cyan-100">
                {robloxFindings.length}
              </span>
            </div>
            {robloxFindings.length > 0 ? (
              <div className="mt-3 flex flex-wrap gap-2">
                {robloxFindings.slice(0, 8).map((finding) => (
                  <span
                    className={`rounded-md border px-2 py-1 text-xs font-semibold ${badgeClass(finding.severity)}`}
                    key={finding.id}
                    title={finding.message}
                  >
                    {finding.title}
                  </span>
                ))}
              </div>
            ) : null}
          </div>
          <DataTable
            columns={[
              {
                accessorKey: "severity",
                cell: ({ row }) => <Badge value={row.original.severity} />,
                header: "Severity",
              },
              {
                accessorKey: "title",
                cell: ({ row }) => <TruncatedText value={row.original.title} />,
                header: "Title",
              },
              {
                accessorKey: "message",
                cell: ({ row }) => (
                  <TruncatedText value={row.original.message} />
                ),
                header: "Message",
              },
              {
                accessorKey: "category",
                cell: ({ row }) => <Badge value={row.original.category} />,
                header: "Category",
              },
              {
                accessorKey: "evidence",
                cell: ({ row }) =>
                  row.original.evidence ? (
                    <button
                      className="rounded-md border border-cyan-300/30 bg-cyan-400/10 px-2 py-1 text-xs font-semibold text-cyan-100 transition hover:bg-cyan-400/16"
                      onClick={() => setActiveTab("evidence")}
                      type="button"
                    >
                      {row.original.evidence.title}
                    </button>
                  ) : (
                    <span className="text-slate-500">None</span>
                  ),
                header: "Evidence",
              },
              {
                accessorKey: "confidence",
                header: "Confidence",
              },
              {
                accessorKey: "sourceModule",
                cell: ({ row }) => (
                  <TruncatedText
                    value={row.original.sourceModule ?? "scanner"}
                  />
                ),
                header: "Source",
              },
            ]}
            data={scan.findings}
            emptyMessage="No indications found for this scan."
            searchPlaceholder="Search indication log..."
          />
        </section>
      ) : null}
    </div>
  );
}
