import { defineConfig, devices } from "@playwright/test";

const webUrl = process.env.E2E_WEB_URL ?? "http://localhost:3000";
const apiUrl = process.env.E2E_API_URL ?? "http://localhost:4000";

export default defineConfig({
  expect: {
    timeout: 10_000
  },
  fullyParallel: false,
  outputDir: "test-results",
  reporter: [["list"], ["html", { open: "never" }]],
  testDir: "tests/e2e",
  timeout: 90_000,
  use: {
    baseURL: webUrl,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure"
  },
  webServer: [
    {
      command: "npm run dev:api",
      reuseExistingServer: true,
      timeout: 120_000,
      url: `${apiUrl}/health`
    },
    {
      command: "npm run dev:web",
      reuseExistingServer: true,
      timeout: 120_000,
      url: webUrl
    }
  ],
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] }
    }
  ]
});
