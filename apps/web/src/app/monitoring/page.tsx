import { notFound } from "next/navigation";
import { AppShell } from "@/components/app-shell";
import {
  getAlertNotifications,
  getMonitoringOverview,
  getSecurityEvents
} from "@/lib/api";
import { getCookieHeader, requireCurrentUser } from "@/lib/session";
import { MonitoringDashboard } from "./monitoring-dashboard";

export default async function MonitoringPage() {
  const cookieHeader = await getCookieHeader();
  const currentUser = await requireCurrentUser(cookieHeader);

  if (currentUser.globalRole !== "SUPER_ADMIN") {
    notFound();
  }

  const [overview, securityEvents, alerts] = await Promise.all([
    getMonitoringOverview(cookieHeader),
    getSecurityEvents({ pageSize: 50 }, cookieHeader),
    getAlertNotifications({ pageSize: 50 }, cookieHeader)
  ]);

  return (
    <AppShell currentUser={currentUser}>
      <MonitoringDashboard
        alerts={alerts.items}
        overview={overview}
        securityEvents={securityEvents.items}
      />
    </AppShell>
  );
}
