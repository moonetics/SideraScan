"use client";

import Image from "next/image";
import {
  Braces,
  Fingerprint,
  Gauge,
  KeyRound,
  MonitorCog,
  ScanSearch,
  Settings,
  UserRoundCog,
  UsersRound
} from "lucide-react";
import type { ReactNode } from "react";
import { LogoutButton } from "@/components/logout-button";
import { NavLink } from "@/components/nav-link";
import type { AuthUser } from "@/lib/api";

type AppShellProps = {
  currentUser: AuthUser;
  children: ReactNode;
};

const navItems = [
  { label: "Dashboard", href: "/", icon: Gauge },
  { label: "Scans", href: "/scans", icon: ScanSearch },
  { label: "Accounts", href: "/accounts", icon: UsersRound },
  {
    adminOnly: true,
    label: "Users",
    href: "/users",
    icon: UserRoundCog
  },
  { label: "Scanner Keys", href: "/scanner-keys", icon: KeyRound },
  { label: "Devices", href: "/devices", icon: Fingerprint },
  { label: "Custom Detections", href: "/custom-detections", icon: Braces },
  { label: "Monitoring", href: "/monitoring", icon: MonitorCog },
  { label: "Settings", href: "/settings", icon: Settings }
];

export function AppShell({ currentUser, children }: AppShellProps) {
  return (
    <main className="min-h-screen px-4 py-4 sm:px-6 lg:px-8">
      <div className="grid w-full gap-6 lg:grid-cols-[260px_minmax(0,1fr)]">
        <aside className="rounded-lg border border-white/10 bg-slate-950/35 p-5 shadow-2xl shadow-slate-950/20 lg:sticky lg:top-4 lg:h-[calc(100vh-2rem)]">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-md border border-cyan-300/20 bg-slate-950/45">
              <Image
                alt="SideraScan logo"
                className="h-9 w-9 object-contain"
                height={36}
                priority
                src="/brand/siderascan-logo-256.png"
                width={36}
              />
            </div>
            <div>
              <p className="text-sm text-slate-300">SideraScan</p>
              <h1 className="text-lg font-semibold">Operations</h1>
            </div>
          </div>

          <div className="mt-6 rounded-md border border-white/10 bg-white/5 p-3">
            <p className="text-sm font-medium text-slate-100">
              {currentUser.displayName}
            </p>
            <p className="mt-1 text-xs text-slate-400">
              {currentUser.globalRole.replace("_", " ")}
            </p>
          </div>

          <nav className="mt-8 space-y-2 text-sm text-slate-300">
            {navItems
              .filter(
                (item) =>
                  !("adminOnly" in item) ||
                  currentUser.globalRole === "SUPER_ADMIN"
              )
              .map((item) => {
              const Icon = item.icon;

              return (
                <NavLink
                  href={item.href}
                  icon={Icon}
                  key={item.label}
                  label={item.label}
                />
              );
            })}
          </nav>
        </aside>

        <section className="min-w-0 rounded-lg border border-white/10 bg-slate-950/30 p-6 shadow-2xl shadow-slate-950/20">
          <div className="mb-6 flex justify-end">
            <LogoutButton />
          </div>
          {children}
        </section>
      </div>
    </main>
  );
}
