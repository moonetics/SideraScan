import { randomBytes, createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { expect, request as playwrightRequest, test, type APIRequestContext, type Page } from "@playwright/test";

const WEB_URL = process.env.E2E_WEB_URL ?? "http://localhost:3000";
const API_URL = process.env.E2E_API_URL ?? "http://localhost:4000";
const ADMIN_IDENTIFIER =
  process.env.E2E_ADMIN_IDENTIFIER ?? "admin@example.com";
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "ChangeMe12345!";

type Account = {
  id: string;
  name: string;
  slug: string;
};

type ScannerKeyReveal = {
  rawKey: string;
  scannerKey: {
    id: string;
    keyPrefix: string;
  };
};

type ValidateKeyResponse = {
  valid: true;
  accountId: string;
  accountName: string;
  scanSessionId: string;
  uploadToken: string;
  nonce: string;
};

type ScanDetail = {
  id: string;
  accountId: string;
  device: null | { id: string; fingerprintPrefix: string };
};

const fixture = {
  account: null as Account | null,
  rawScannerKey: "",
  scanId: "",
  deviceId: "",
  viewerIdentifier: "",
  viewerPassword: "ViewerPass12345!"
};

function suffix() {
  return `${Date.now()}-${randomBytes(3).toString("hex")}`;
}

async function expectOk(response: { ok(): boolean; status(): number; text(): Promise<string> }) {
  if (!response.ok()) {
    throw new Error(`Expected OK, got ${response.status()}: ${await response.text()}`);
  }
}

async function createAdminApiContext() {
  const api = await playwrightRequest.newContext({ baseURL: API_URL });
  const login = await api.post("/auth/login", {
    data: {
      identifier: ADMIN_IDENTIFIER,
      password: ADMIN_PASSWORD
    }
  });

  await expectOk(login);

  return api;
}

async function loginViaUi(page: Page, identifier = ADMIN_IDENTIFIER, password = ADMIN_PASSWORD) {
  await page.goto("/login");
  await page.getByLabel("Email or username").fill(identifier);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Login" }).click();
  await expect(page).toHaveURL(WEB_URL + "/");
  await expect(page.getByRole("heading", { name: "Scan review dashboard" })).toBeVisible();
}

async function setupFixture(api: APIRequestContext) {
  const unique = suffix();
  const accountName = `E2E Account ${unique}`;
  const accountSlug = `e2e-${unique}`;
  const accountResponse = await api.post("/accounts", {
    data: { name: accountName, slug: accountSlug }
  });

  await expectOk(accountResponse);
  const account = (await accountResponse.json()) as Account;
  fixture.account = account;

  const viewerEmail = `viewer-${unique}@example.com`;
  const viewerUsername = `viewer-${unique}`;
  const viewerResponse = await api.post("/users", {
    data: {
      displayName: `Viewer ${unique}`,
      email: viewerEmail,
      password: fixture.viewerPassword,
      username: viewerUsername
    }
  });
  await expectOk(viewerResponse);
  const viewer = (await viewerResponse.json()) as { id: string };
  fixture.viewerIdentifier = viewerEmail;

  const assignmentResponse = await api.post(`/accounts/${account.id}/users`, {
    data: {
      role: "VIEWER",
      userId: viewer.id
    }
  });
  await expectOk(assignmentResponse);

  const keyResponse = await api.post(`/accounts/${account.id}/scanner-keys`, {
    data: {
      allowedScannerVersions: ["0.1.0"],
      expiresAt: null,
      name: `E2E Key ${unique}`,
      rateLimitPerHour: 60
    }
  });
  await expectOk(keyResponse);
  const key = (await keyResponse.json()) as ScannerKeyReveal;
  fixture.rawScannerKey = key.rawKey;

  const publicApi = await playwrightRequest.newContext({ baseURL: API_URL });
  const validateResponse = await publicApi.post("/scanner/validate-key", {
    data: {
      arch: "amd64",
      platform: "windows",
      playerLabel: `E2E Player ${unique}`,
      scannerKey: key.rawKey,
      scannerVersion: "0.1.0"
    }
  });
  await expectOk(validateResponse);
  const validated = (await validateResponse.json()) as ValidateKeyResponse;
  const now = new Date();
  const finished = new Date(now.getTime() + 35_000);
  const fingerprintHash = createHash("sha256")
    .update(`siderascan-e2e-${unique}`)
    .digest("hex");

  const resultsResponse = await publicApi.post(
    `/scanner/sessions/${validated.scanSessionId}/results`,
    {
      data: {
        auditLog: [
          {
            action: "scan_started",
            createdAt: now.toISOString(),
            source: "e2e"
          }
        ],
        deviceFingerprint: {
          confidence: "HIGH",
          hash: fingerprintHash,
          version: "e2e-v1"
        },
        evidence: [
          {
            clientEvidenceId: "e2e-process",
            data: {
              path: "C:/Users/TestPlayer/Downloads/RobloxTool.exe"
            },
            title: "E2E process evidence",
            type: "process"
          }
        ],
        fileLogs: [
          {
            action: "renamed_file",
            confidence: 88,
            newPath: "C:/Users/TestPlayer/Documents/renamed.exe",
            oldPath: "C:/Users/TestPlayer/Downloads/source.exe",
            severity: "WARNING",
            source: "e2e_file_log",
            timestamp: now.toISOString()
          }
        ],
        findings: [
          {
            category: "CUSTOM_DETECTION",
            confidence: 91,
            evidenceRef: "e2e-process",
            message: "E2E suspicious process matched a test signature.",
            severity: "WARNING",
            sourceModule: "roblox_e2e",
            title: "E2E custom detection"
          }
        ],
        finishedAt: finished.toISOString(),
        launcherProfiles: [
          {
            launcherType: "Bloxstrap",
            path: "C:/Users/TestPlayer/AppData/Local/Bloxstrap/Bloxstrap.exe",
            profileName: "Bloxstrap",
            publisher: "Bloxstrap",
            status: "normal",
            tags: ["third_party"]
          }
        ],
        modules: [
          {
            durationMs: 1200,
            moduleName: "overview",
            status: "completed"
          },
          {
            durationMs: 800,
            moduleName: "roblox_file_logs",
            status: "completed"
          }
        ],
        networkSnapshot: {
          connectionType: "Ethernet",
          country: "Indonesia"
        },
        nonce: validated.nonce,
        overview: {
          bootTime: now.toISOString(),
          connectionType: "Ethernet",
          country: "Indonesia",
          os: "Windows 11",
          scanSpeed: "35s",
          vm: "No"
        },
        processTimeline: [
          {
            path: "C:/Users/TestPlayer/Downloads/RobloxTool.exe",
            processName: "RobloxTool.exe",
            startedAt: now.toISOString(),
            status: "suspicious"
          }
        ],
        processTimes: [
          {
            durationMs: 35000,
            path: "C:/Users/TestPlayer/AppData/Local/Roblox/RobloxPlayerBeta.exe",
            processName: "RobloxPlayerBeta.exe",
            source: "e2e",
            startedAt: now.toISOString(),
            status: "normal"
          }
        ],
        startedAt: now.toISOString(),
        systemIdentity: {
          os: "Windows 11"
        },
        uploadToken: validated.uploadToken,
        utilities: [
          {
            name: "E2E Utility",
            scope: "roblox",
            status: "normal"
          }
        ],
        windowsItems: [
          {
            name: "DiagTrack",
            scope: "roblox",
            status: "normal",
            type: "service"
          }
        ]
      }
    }
  );
  await expectOk(resultsResponse);

  const completeResponse = await publicApi.post(
    `/scanner/sessions/${validated.scanSessionId}/complete`,
    {
      data: {
        nonce: validated.nonce,
        status: "COMPLETED",
        uploadToken: validated.uploadToken
      }
    }
  );
  await expectOk(completeResponse);
  fixture.scanId = validated.scanSessionId;

  const detailResponse = await api.get(`/scans/${fixture.scanId}`);
  await expectOk(detailResponse);
  const detail = (await detailResponse.json()) as ScanDetail;
  fixture.deviceId = detail.device?.id ?? "";

  await publicApi.dispose();
}

test.describe.serial("SideraScan web e2e", () => {
  test.beforeAll(async () => {
    const api = await createAdminApiContext();
    await setupFixture(api);
    await api.dispose();
  });

  test("redirects protected routes and logs in through the UI", async ({ page }) => {
    await page.goto("/settings");
    await expect(page).toHaveURL(/\/login/);
    await expect(page.getByRole("heading", { name: "Dashboard login" })).toBeVisible();

    await loginViaUi(page);
    await expect(page.getByAltText("SideraScan logo").first()).toBeVisible();
  });

  test("loads all primary and detail routes without runtime errors", async ({ page }) => {
    await loginViaUi(page);
    const account = fixture.account;

    if (!account) {
      throw new Error("Missing account fixture");
    }

    const routes = [
      { heading: "Scan review dashboard", path: "/" },
      { heading: "Accounts", path: "/accounts" },
      { heading: account.name, path: `/accounts/${account.id}` },
      { heading: "Users", path: "/users" },
      { heading: "Scanner Keys", path: "/scanner-keys" },
      { heading: "Scans", path: "/scans" },
      { heading: /E2E Player/, path: `/scans/${fixture.scanId}` },
      { heading: "Devices", path: "/devices" },
      { heading: /dfp_/, path: `/devices/${fixture.deviceId}` },
      { heading: "Custom Detections", path: "/custom-detections" },
      { heading: "Monitoring", path: "/monitoring" },
      { heading: "Settings", path: "/settings" }
    ];

    for (const route of routes) {
      await page.goto(route.path);
      await expect(page.getByRole("heading", { name: route.heading })).toBeVisible();
      await expect(page.getByText("Runtime Error")).toHaveCount(0);
      await expect(page.getByText("Cannot read properties")).toHaveCount(0);
    }
  });

  test("covers core production buttons and forms", async ({ page }) => {
    await loginViaUi(page);
    const unique = suffix();
    const account = fixture.account;

    if (!account) {
      throw new Error("Missing account fixture");
    }

    await page.goto("/accounts");
    const createAccountForm = page.locator("form").filter({ hasText: "Create account" });
    await createAccountForm.getByLabel("Name").fill(`UI Account ${unique}`);
    await createAccountForm.getByLabel("Slug").fill(`ui-${unique}`);
    await createAccountForm.getByRole("button", { name: /Create/ }).click();
    await expect(page.getByText(`UI Account ${unique}`)).toBeVisible();

    await page.getByText(`UI Account ${unique}`).click();
    await expect(page.getByRole("link", { name: "Manage access" }).first()).toBeVisible();
    await expect(page.getByRole("heading", { name: "Create user" })).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "Assign role" })).toHaveCount(0);

    await page.goto("/users");
    const createUserForm = page
      .locator("form")
      .filter({ hasText: "Create dashboard user" });
    await createUserForm.getByPlaceholder("Display name").fill(`UI User ${unique}`);
    await createUserForm
      .getByPlaceholder("email@example.com")
      .fill(`ui-user-${unique}@example.com`);
    await createUserForm.getByPlaceholder("username").fill(`ui-user-${unique}`);
    await createUserForm
      .getByPlaceholder("Initial password, min 12 chars")
      .fill("UiUserPass12345!");
    await createUserForm.getByRole("button", { name: "Create" }).click();
    await expect(page.getByText(`UI User ${unique}`)).toBeVisible();
    await expect(page.getByText("Unassigned").first()).toBeVisible();

    await page.goto("/scanner-keys");
    const keyForm = page.locator("form").filter({ hasText: "Generate scanner key" });
    await keyForm.getByLabel("Account").selectOption({ label: account.name });
    await keyForm.getByLabel("Name").fill(`UI Key ${unique}`);
    await keyForm.getByLabel("Rate/hour").fill("30");
    await keyForm.getByLabel("Allowed versions").fill("0.1.0");
    await keyForm.getByRole("button", { name: /Generate key/ }).click();
    await expect(page.getByText("New scanner key")).toBeVisible();
    await expect(page.getByText(/^sds_live_[A-Z0-9]{4}-/)).toBeVisible();
    await page.getByRole("button", { name: "Copy once" }).click();
    await page.getByTitle("Rotate key").first().click();
    await expect(page.getByText("Rotated scanner key")).toBeVisible();
    await page.getByTitle("Revoke key").first().click();
    await expect(page.getByText("REVOKED").first()).toBeVisible();

    await page.goto("/custom-detections");
    const ruleName = `E2E Rule ${unique}`;
    const ruleForm = page.locator("form").filter({ hasText: "Create rule" });
    await ruleForm.getByLabel("Name", { exact: true }).fill(ruleName);
    await ruleForm.getByLabel("Scope").selectOption("GLOBAL");
    await ruleForm.getByLabel("Values", { exact: true }).fill("RobloxTool.exe");
    await ruleForm.getByRole("button", { name: "Create rule" }).click();
    await expect(page.getByText(ruleName)).toBeVisible();

    const samplePath = join(tmpdir(), `siderascan-e2e-${unique}.bin`);
    writeFileSync(samplePath, Buffer.from("alpha\0RobloxUniqueString\0executor-marker"));
    const uploadForm = page.locator("form").filter({ hasText: "String Builder" });
    await uploadForm.getByLabel("Sample", { exact: true }).setInputFiles(samplePath);
    await uploadForm.getByRole("button", { name: "Upload and extract" }).click();
    await expect(page.getByText(/strings - PURGED|strings - EXTRACTED/)).toBeVisible();

    await page.goto("/settings");
    await page.getByRole("button", { name: "Save policy" }).click();
    await expect(page.getByText("Retention settings saved and audited.")).toBeVisible();
    await page.getByRole("button", { name: "Run dry run" }).click();
    await expect(page.getByText("Dry run complete. No records were deleted.")).toBeVisible();

    await page.goto(`/scans/${fixture.scanId}`);
    const [htmlDownload] = await Promise.all([
      page.waitForEvent("download"),
      page.getByRole("link", { name: "HTML report" }).click()
    ]);
    expect(htmlDownload.suggestedFilename()).toMatch(/siderascan-report-.*\.html/);

    const [jsonDownload] = await Promise.all([
      page.waitForEvent("download"),
      page.getByRole("link", { name: "JSON report" }).click()
    ]);
    expect(jsonDownload.suggestedFilename()).toMatch(/siderascan-report-.*\.json/);

    await page.getByRole("button", { name: "Logout" }).click();
    await expect(page).toHaveURL(/\/login/);
  });

  test("hides export actions from viewer users", async ({ page }) => {
    await loginViaUi(page, fixture.viewerIdentifier, fixture.viewerPassword);
    await page.goto(`/scans/${fixture.scanId}`);
    await expect(page.getByRole("heading", { name: /E2E Player/ })).toBeVisible();
    await expect(page.getByRole("link", { name: "HTML report" })).toHaveCount(0);
    await expect(page.getByRole("link", { name: "JSON report" })).toHaveCount(0);
  });
});
