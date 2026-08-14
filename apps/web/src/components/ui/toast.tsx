"use client";

import { CheckCircle2, Info, X, XCircle } from "lucide-react";
import {
  createContext,
  ReactNode,
  useCallback,
  useContext,
  useMemo,
  useState
} from "react";

type ToastTone = "error" | "info" | "success";

type ToastItem = {
  id: string;
  message: string;
  tone: ToastTone;
};

type ToastContextValue = {
  error: (message: string) => void;
  info: (message: string) => void;
  success: (message: string) => void;
};

const ToastContext = createContext<ToastContextValue | null>(null);

const toneClass: Record<ToastTone, string> = {
  error: "border-rose-300/30 bg-rose-500/14 text-rose-50",
  info: "border-cyan-300/30 bg-cyan-500/14 text-cyan-50",
  success: "border-emerald-300/30 bg-emerald-500/14 text-emerald-50"
};

const toneIcon = {
  error: XCircle,
  info: Info,
  success: CheckCircle2
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const remove = useCallback((id: string) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const push = useCallback(
    (tone: ToastTone, message: string) => {
      const id = crypto.randomUUID();
      setToasts((current) => [{ id, message, tone }, ...current].slice(0, 4));
      window.setTimeout(() => remove(id), 4200);
    },
    [remove]
  );

  const value = useMemo(
    () => ({
      error: (message: string) => push("error", message),
      info: (message: string) => push("info", message),
      success: (message: string) => push("success", message)
    }),
    [push]
  );

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="fixed right-4 top-4 z-50 grid w-[min(420px,calc(100vw-2rem))] gap-3">
        {toasts.map((toast) => {
          const Icon = toneIcon[toast.tone];

          return (
            <div
              className={`flex items-start gap-3 rounded-lg border px-4 py-3 shadow-2xl shadow-slate-950/30 backdrop-blur ${toneClass[toast.tone]}`}
              key={toast.id}
              role="status"
            >
              <Icon className="mt-0.5 h-4 w-4 shrink-0" />
              <p className="min-w-0 flex-1 text-sm font-medium">
                {toast.message}
              </p>
              <button
                aria-label="Dismiss notification"
                className="rounded p-1 opacity-75 transition hover:bg-white/10 hover:opacity-100"
                onClick={() => remove(toast.id)}
                type="button"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const value = useContext(ToastContext);

  if (!value) {
    throw new Error("useToast must be used within ToastProvider");
  }

  return value;
}
