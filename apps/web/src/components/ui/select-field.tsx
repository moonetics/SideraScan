"use client";

import { ChevronDown } from "lucide-react";
import type { SelectHTMLAttributes } from "react";

type SelectFieldProps = SelectHTMLAttributes<HTMLSelectElement>;

export function SelectField({ className = "", children, ...props }: SelectFieldProps) {
  return (
    <span className="relative mt-2 block">
      <select
        className={`h-10 w-full appearance-none rounded-md border border-white/10 bg-slate-950/45 py-0 pl-3 pr-10 text-sm text-slate-100 outline-none transition focus:border-cyan-300/70 ${className}`}
        {...props}
      >
        {children}
      </select>
      <ChevronDown
        aria-hidden="true"
        className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-300"
      />
    </span>
  );
}
