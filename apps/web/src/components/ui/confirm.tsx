"use client";

import { AlertTriangle, X } from "lucide-react";
import {
  createContext,
  ReactNode,
  useCallback,
  useContext,
  useMemo,
  useState
} from "react";

type ConfirmOptions = {
  cancelLabel?: string;
  confirmLabel?: string;
  description: string;
  title: string;
  variant?: "danger" | "default";
};

type PendingConfirm = ConfirmOptions & {
  resolve: (value: boolean) => void;
};

const ConfirmContext = createContext<((options: ConfirmOptions) => Promise<boolean>) | null>(
  null
);

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<PendingConfirm | null>(null);

  const confirm = useCallback((options: ConfirmOptions) => {
    return new Promise<boolean>((resolve) => {
      setPending({ ...options, resolve });
    });
  }, []);

  const value = useMemo(() => confirm, [confirm]);

  function close(result: boolean) {
    pending?.resolve(result);
    setPending(null);
  }

  return (
    <ConfirmContext.Provider value={value}>
      {children}
      {pending ? (
        <div
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/72 px-4 backdrop-blur-sm"
          role="dialog"
        >
          <div className="w-full max-w-md rounded-lg border border-white/10 bg-[#172842] p-5 shadow-2xl shadow-slate-950/40">
            <div className="flex items-start gap-3">
              <div
                className={`rounded-md border p-2 ${
                  pending.variant === "danger"
                    ? "border-rose-300/30 bg-rose-500/12 text-rose-100"
                    : "border-cyan-300/30 bg-cyan-500/12 text-cyan-100"
                }`}
              >
                <AlertTriangle className="h-5 w-5" />
              </div>
              <div className="min-w-0 flex-1">
                <h2 className="text-lg font-semibold text-slate-100">
                  {pending.title}
                </h2>
                <p className="mt-2 text-sm leading-6 text-slate-300">
                  {pending.description}
                </p>
              </div>
              <button
                aria-label="Close confirmation"
                className="rounded-md p-1 text-slate-400 transition hover:bg-white/8 hover:text-slate-100"
                onClick={() => close(false)}
                type="button"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="mt-5 flex justify-end gap-2">
              <button
                className="h-10 rounded-md border border-white/10 px-4 text-sm font-semibold text-slate-200 transition hover:bg-white/8"
                onClick={() => close(false)}
                type="button"
              >
                {pending.cancelLabel ?? "Cancel"}
              </button>
              <button
                className={`h-10 rounded-md px-4 text-sm font-semibold transition ${
                  pending.variant === "danger"
                    ? "bg-rose-500 text-white hover:bg-rose-400"
                    : "bg-cyan-500 text-slate-950 hover:bg-cyan-300"
                }`}
                onClick={() => close(true)}
                type="button"
              >
                {pending.confirmLabel ?? "Confirm"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </ConfirmContext.Provider>
  );
}

export function useConfirm() {
  const value = useContext(ConfirmContext);

  if (!value) {
    throw new Error("useConfirm must be used within ConfirmProvider");
  }

  return value;
}
