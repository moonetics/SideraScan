import { CheckCircle2, XCircle } from "lucide-react";
import { ReactNode } from "react";
import { cn } from "@/lib/utils";

type StatusPillProps = {
  status: "ok" | "error" | "unknown";
  children: ReactNode;
};

export function StatusPill({ status, children }: StatusPillProps) {
  const Icon = status === "ok" ? CheckCircle2 : XCircle;

  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 rounded-md border px-3 py-1 text-sm font-medium",
        status === "ok" &&
          "border-teal-300/30 bg-teal-400/10 text-teal-100",
        status === "error" &&
          "border-rose-300/30 bg-rose-400/10 text-rose-100",
        status === "unknown" &&
          "border-slate-300/30 bg-slate-400/10 text-slate-100"
      )}
    >
      <Icon className="h-4 w-4" />
      {children}
    </span>
  );
}
