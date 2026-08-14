import { notFound } from "next/navigation";
import { AppShell } from "@/components/app-shell";
import { getRetentionSettings } from "@/lib/api";
import { getCookieHeader, requireCurrentUser } from "@/lib/session";
import { RetentionSettingsPanel } from "./retention-settings-panel";

export default async function SettingsPage() {
  const cookieHeader = await getCookieHeader();
  const currentUser = await requireCurrentUser(cookieHeader);

  if (currentUser.globalRole !== "SUPER_ADMIN") {
    notFound();
  }

  const retention = await getRetentionSettings(cookieHeader);

  return (
    <AppShell currentUser={currentUser}>
      <div className="border-b border-white/10 pb-6">
        <p className="text-sm font-medium text-cyan-200">Production controls</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-normal">
          Settings
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">
          Configure retention policy and production safety controls. Phase 11
          retention only performs dry-run counts and never deletes records.
        </p>
      </div>

      <RetentionSettingsPanel initialRetention={retention} />
    </AppShell>
  );
}
