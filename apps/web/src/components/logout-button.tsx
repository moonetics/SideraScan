"use client";

import { LogOut } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { logout } from "@/lib/api";

export function LogoutButton() {
  const router = useRouter();
  const [isPending, setIsPending] = useState(false);

  async function handleLogout() {
    setIsPending(true);

    try {
      await logout();
      router.replace("/login");
      router.refresh();
    } finally {
      setIsPending(false);
    }
  }

  return (
    <button
      className="inline-flex h-10 items-center gap-2 rounded-md border border-white/10 bg-white/8 px-3 text-sm font-medium text-slate-100 transition hover:bg-white/12 disabled:cursor-not-allowed disabled:opacity-60"
      disabled={isPending}
      onClick={handleLogout}
      type="button"
    >
      <LogOut className="h-4 w-4" />
      {isPending ? "Signing out" : "Logout"}
    </button>
  );
}

