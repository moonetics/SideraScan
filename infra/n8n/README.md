# SideraScan n8n Self-Hosting

This folder contains the self-hosted n8n runtime configuration for SideraScan.

Phase 2 adds importable workflow skeletons for signed SideraScan webhooks.
Phase 3 turns the `scan.completed` workflow into an advisory AI Review workflow using a provider-agnostic layout with Gemini as the default dev/testing provider.

For production deployment, backup, restore, update, rollback, and smoke-test operations, use [N8N_RUNBOOK.md](../../docs/N8N_RUNBOOK.md).

## Environment Separation

SideraScan API env lives in `.env.example` and `apps/api/.env.example`.

Those API variables control outbound webhooks from SideraScan to n8n:

```env
N8N_WEBHOOK_ENABLED=false
N8N_SCAN_COMPLETED_WEBHOOK_URL=http://localhost:5678/webhook/siderascan-scan-completed
N8N_ALERT_WEBHOOK_ENABLED=false
N8N_ALERT_WEBHOOK_URL=http://localhost:5678/webhook/siderascan-security-alert
N8N_WEBHOOK_SECRET=dev-only-change-n8n-webhook-secret-32-chars
APP_DASHBOARD_URL=http://localhost:3000
```

n8n runtime env lives in `infra/n8n/.env.example`.

Those variables belong to the n8n container and its PostgreSQL database:

```env
N8N_HOST=n8n.example.com
N8N_PROTOCOL=https
N8N_PORT=5678
WEBHOOK_URL=https://n8n.example.com/
N8N_ENCRYPTION_KEY=<generate-long-random-secret>
N8N_DB_PASSWORD=<generate-strong-password>
SIDERASCAN_WEBHOOK_SECRET=<same-as-api-N8N_WEBHOOK_SECRET>
NODE_FUNCTION_ALLOW_BUILTIN=crypto,https,process
N8N_BLOCK_ENV_ACCESS_IN_NODE=false
AI_PROVIDER=gemini
GEMINI_MODEL=gemini-3.6-flash
SIDERASCAN_API_BASE_URL=http://host.docker.internal:4000
SIDERASCAN_AI_PROMPT_VERSION=n8n-ai-review-v1
DISCORD_SECURITY_ALERT_WEBHOOK_ENABLED=false
DISCORD_SECURITY_ALERT_WEBHOOK_URL=<discord-webhook-url>
```

Do not put n8n container secrets in the SideraScan API env, and do not put SideraScan database/auth secrets in the n8n env.

## Local Development Defaults

Local development keeps n8n disabled:

```env
N8N_WEBHOOK_ENABLED=false
N8N_ALERT_WEBHOOK_ENABLED=false
```

With this default, scan completion must still succeed. The backend records disabled/skipped automation state instead of failing the scanner flow.

Scanner advanced forensic mode is selected by SideraScan API:

- `review_relevant_only`: used when n8n scan review is disabled or no scan completed webhook URL is configured.
- `ai_assisted_full`: used only when `N8N_WEBHOOK_ENABLED=true` and `N8N_SCAN_COMPLETED_WEBHOOK_URL` is configured.

The scanner never talks directly to n8n.

## Secret Policy

Never commit real values for:

- `N8N_WEBHOOK_SECRET`
- `N8N_ENCRYPTION_KEY`
- `N8N_DB_PASSWORD`
- production dashboard/API URLs if they reveal private infrastructure

Use generated production secrets only in untracked deployment env files.

## Docker Compose

Create an untracked runtime env first:

```powershell
Copy-Item infra/n8n/.env.example infra/n8n/.env
```

Edit `infra/n8n/.env` and replace:

- `N8N_ENCRYPTION_KEY`
- `N8N_DB_PASSWORD`
- `DB_POSTGRESDB_PASSWORD`
- `SIDERASCAN_WEBHOOK_SECRET`
- `N8N_HOST`
- `WEBHOOK_URL`

The n8n image is pinned by `N8N_IMAGE_TAG`. Do not use `latest` for production.

`SIDERASCAN_WEBHOOK_SECRET` must match the SideraScan API value `N8N_WEBHOOK_SECRET`. The workflow Code nodes also require:

```env
NODE_FUNCTION_ALLOW_BUILTIN=crypto,https,process
N8N_BLOCK_ENV_ACCESS_IN_NODE=false
SIDERASCAN_SIGNATURE_TOLERANCE_SECONDS=300
```

This is acceptable only for trusted self-hosted workflows controlled by the SideraScan admin.

## Commands

Validate Compose:

```powershell
docker compose --env-file infra/n8n/.env.example -f infra/n8n/docker-compose.n8n.yml config
```

Start:

```powershell
docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml up -d
```

Stop:

```powershell
docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml down
```

Logs:

```powershell
docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml logs -f n8n
```

PostgreSQL logs:

```powershell
docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml logs -f n8n-postgres
```

Backup database:

```powershell
docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml exec n8n-postgres pg_dump -U n8n -d n8n > n8n-backup.sql
```

## Local Access

For local development, n8n is bound to localhost only:

```text
http://localhost:5678
```

The n8n PostgreSQL service has no public `ports` mapping.

## Workflow Templates

Import these files in the n8n editor:

- `infra/n8n/workflows/siderascan-ai-review.workflow.json`
- `infra/n8n/workflows/siderascan-security-alert.workflow.json`

Import flow:

1. Open `http://localhost:5678`.
2. Go to **Workflows**.
3. Choose **Import from File**.
4. Select one workflow JSON file.
5. Save it.
6. For local testing, open the workflow and click **Listen for test event**.
7. After testing, activate the workflow to use the production webhook path.

Webhook URLs while editing:

```text
http://localhost:5678/webhook-test/siderascan-scan-completed
http://localhost:5678/webhook-test/siderascan-security-alert
```

Webhook URLs after activation:

```text
http://localhost:5678/webhook/siderascan-scan-completed
http://localhost:5678/webhook/siderascan-security-alert
```

In production, use your HTTPS `WEBHOOK_URL` domain instead of localhost.

## AI Review Workflow

The AI Review workflow receives the redacted `scan.completed` event from SideraScan API, verifies the HMAC signature, responds `accepted` immediately, asks an AI provider for an advisory JSON review, validates the JSON shape, signs the callback, and posts it to SideraScan API:

```text
POST /scan-reviews
```

Default dev/testing provider:

```env
AI_PROVIDER=gemini
GEMINI_MODEL=gemini-3.6-flash
SIDERASCAN_API_BASE_URL=http://host.docker.internal:4000
SIDERASCAN_AI_PROMPT_VERSION=n8n-ai-review-v1
```

`host.docker.internal` is used because n8n runs inside Docker and the local SideraScan API usually runs on the host at port `4000`. In production, set `SIDERASCAN_API_BASE_URL` to the private or public HTTPS API URL reachable from the n8n container.

### Gemini Credential

Create the Gemini key in Google AI Studio, then store it in n8n Credentials. Do not put the Gemini API key in workflow JSON or committed env examples.

In n8n:

1. Open **Credentials**.
2. Create **HTTP Header Auth**.
3. Name it exactly `Gemini API Key`.
4. Set header name to `x-goog-api-key`.
5. Set header value to your Gemini API key.
6. Save.
7. Open the imported `SideraScan - AI Review` workflow.
8. Select the `Call Gemini` node and choose the `Gemini API Key` credential. The workflow template intentionally does not include a credential ID because IDs are local to each n8n instance.

If `Call Gemini` fails with `Found credential with no ID`, reopen the node, reselect `Gemini API Key`, save the workflow, then deactivate and activate the workflow again.

Gemini Free Tier is acceptable for local/dev testing, but it has quotas/rate limits and no production SLA. For production, either monitor quota failures carefully or switch to a paid provider/tier.

### Advisory Safety

The AI workflow is advisory only. It may call only `POST /scan-reviews`; it must not call device mark, ban, account, scanner key, or rule mutation endpoints.

Allowed `recommendedAction` values:

- `NO_ACTION`
- `MONITOR`
- `REQUEST_RESCAN`
- `MANUAL_REVIEW`
- `ESCALATE`

The workflow rejects malformed JSON, `AUTO_BAN`, direct ban/punishment language, and HWID-ban language before calling SideraScan API.

### Provider Swap

The workflow is provider-agnostic at the boundary: normalize input, build prompt, validate JSON, and sign callback are separate nodes. To swap provider later:

1. Keep the webhook verification, normalization, prompt, validation, signing, and callback nodes.
2. Replace only the provider call node, for example OpenAI, DeepSeek, or Ollama.
3. Keep the output JSON schema and advisory safety validator unchanged.

## Security Alert Workflow

The Security Alert workflow receives redacted `security.alert` events from SideraScan API, verifies the HMAC signature, responds `accepted` immediately, normalizes metadata again, and sends high/critical alerts to Discord when the sink is enabled.

Runtime env:

```env
DISCORD_SECURITY_ALERT_WEBHOOK_ENABLED=false
DISCORD_SECURITY_ALERT_WEBHOOK_URL=<discord-webhook-url>
```

To enable Discord locally:

1. In Discord, open the target server/channel.
2. Create an incoming webhook for the channel.
3. Copy the webhook URL.
4. Put the URL only in untracked `infra/n8n/.env`.
5. Set `DISCORD_SECURITY_ALERT_WEBHOOK_ENABLED=true`.
6. Restart n8n:

```powershell
docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml up -d
```

The workflow sends Discord messages only for `HIGH` and `CRITICAL`. `INFO` and `WARNING` events are accepted and visible in n8n execution history, but they are not sent to Discord.

The workflow never commits or stores the Discord webhook URL in tracked workflow JSON. The `Send Discord alert` Code node reads the URL at runtime from `process.env.DISCORD_SECURITY_ALERT_WEBHOOK_URL`. Do not replace that with an n8n `$env` expression, because the editor preview can show `$env` as `undefined` even when the container env is configured.

Alert Discord embed includes:

- severity
- service
- event type
- message
- dashboard URL
- created time
- idempotency key
- capped redacted metadata summary

The metadata formatter removes secret-like keys and masks private user paths again, even though the SideraScan API already sends redacted payloads.

## Signed Webhook Test

Use this PowerShell sample while a workflow is listening for a test event. It reads the local untracked n8n env and sends a redacted dummy `scan.completed` event.

```powershell
$envText = Get-Content infra/n8n/.env -Raw
$secretMatch = [regex]::Match($envText, 'SIDERASCAN_WEBHOOK_SECRET="?([^"\r\n]+)"?')
if (-not $secretMatch.Success) { throw "SIDERASCAN_WEBHOOK_SECRET is missing in infra/n8n/.env" }
$secret = $secretMatch.Groups[1].Value

$payload = [ordered]@{
  event = "scan.completed"
  scanSessionId = "11111111-1111-4111-8111-111111111111"
  accountId = "test-account"
  riskScore = 0
  severity = "INFO"
  findingCount = 0
  dashboardUrl = "http://localhost:3000/scans/11111111-1111-4111-8111-111111111111"
  metadata = @{ source = "n8n-skeleton-test" }
}

$body = $payload | ConvertTo-Json -Depth 8 -Compress
$timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
$hmac = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($secret))
$hash = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes("$timestamp.$body"))
$signature = "sha256=" + (($hash | ForEach-Object { $_.ToString("x2") }) -join "")

Invoke-RestMethod `
  -Uri "http://localhost:5678/webhook-test/siderascan-scan-completed" `
  -Method Post `
  -ContentType "application/json" `
  -Headers @{
    "x-siderascan-timestamp" = $timestamp
    "x-siderascan-signature" = $signature
    "x-idempotency-key" = "scan.completed:11111111-1111-4111-8111-111111111111"
    "x-siderascan-event" = "scan.completed"
  } `
  -Body $body
```

Expected response:

```json
{
  "status": "accepted",
  "event": "scan.completed",
  "idempotencyKey": "scan.completed:11111111-1111-4111-8111-111111111111"
}
```

For `security.alert`, change `event`, the idempotency key prefix, and the URL path to `siderascan-security-alert`.

If you run this against the full AI Review workflow with the Gemini credential configured, the workflow will continue after the accepted response and attempt the Gemini call plus `/scan-reviews` callback.

Security alert test payload:

```powershell
$envText = Get-Content infra/n8n/.env -Raw
$secretMatch = [regex]::Match($envText, 'SIDERASCAN_WEBHOOK_SECRET="?([^"\r\n]+)"?')
if (-not $secretMatch.Success) { throw "SIDERASCAN_WEBHOOK_SECRET is missing in infra/n8n/.env" }
$secret = $secretMatch.Groups[1].Value

$payload = [ordered]@{
  event = "security.alert"
  severity = "HIGH"
  service = "siderascan-api"
  eventType = "N8N_SIGNATURE_INVALID_TEST"
  message = "Signed security alert workflow test."
  dashboardUrl = "http://localhost:3000/monitoring"
  createdAt = [DateTimeOffset]::UtcNow.ToString("o")
  metadata = @{
    source = "n8n-security-alert-test"
    scannerKey = "should-be-redacted"
    path = "C:\Users\TestUser\AppData\Local\Temp\sample.exe"
  }
}

$body = $payload | ConvertTo-Json -Depth 8 -Compress
$timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
$hmac = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($secret))
$hash = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes("$timestamp.$body"))
$signature = "sha256=" + (($hash | ForEach-Object { $_.ToString("x2") }) -join "")

Invoke-RestMethod `
  -Uri "http://localhost:5678/webhook-test/siderascan-security-alert" `
  -Method Post `
  -ContentType "application/json" `
  -Headers @{
    "x-siderascan-timestamp" = $timestamp
    "x-siderascan-signature" = $signature
    "x-idempotency-key" = "security.alert:test-high"
    "x-siderascan-event" = "security.alert"
  } `
  -Body $body
```

Expected response:

```json
{
  "status": "accepted",
  "event": "security.alert",
  "idempotencyKey": "security.alert:test-high"
}
```

If Discord is enabled and the workflow is active/listening, a `HIGH` or `CRITICAL` payload sends a Discord embed. Change severity to `WARNING` to confirm the workflow accepts the event but suppresses Discord delivery.

Phase 2 validates that an idempotency key exists. Stateful duplicate handling belongs to the production workflow phase or to SideraScan API idempotency.

The workflow templates never persist or echo the incoming payload. They only return the minimal accepted response.

## Fallback and Review Mode Validation

Phase 5 validates that n8n changes the scanner forensic upload mode without becoming a scanner dependency.

Expected SideraScan API behavior:

- `N8N_WEBHOOK_ENABLED=true` plus a configured `N8N_SCAN_COMPLETED_WEBHOOK_URL` returns `advancedForensics.reviewMode=ai_assisted_full` from `POST /scanner/config`.
- `N8N_WEBHOOK_ENABLED=false` returns `advancedForensics.reviewMode=review_relevant_only`.
- `N8N_WEBHOOK_ENABLED=true` with no scan completed webhook URL also returns `review_relevant_only`.
- If n8n is offline or returns an error during `scan.completed`, scanner upload and complete still succeed; the failed automation state is stored in `automation_events` and shown in scan detail and Monitoring.
- Dashboard retry uses `POST /scans/:id/ai-review/retry`; it re-sends the backend-generated redacted `scan.completed` event and does not perform any automatic ban.

Validation checklist:

1. Start API with n8n disabled and request scanner config with a valid scanner key. Confirm `review_relevant_only`.
2. Start API with n8n enabled and the local active webhook URL. Confirm `ai_assisted_full`.
3. Stop n8n, run a scanner upload, and confirm the scan still completes.
4. Open the scan detail AI Review tab and confirm n8n status, attempts, and last error are visible.
5. Restart n8n and use **Retry Review** from the dashboard to confirm the automation event can be sent again.

The scanner `.exe` must never call n8n directly. It only calls the SideraScan API for key validation, scanner config, result upload, section upload, and session completion.

## Production Notes

- Put n8n behind HTTPS reverse proxy.
- Keep `WEBHOOK_URL` set to the public HTTPS n8n domain.
- Do not expose `n8n-postgres` publicly.
- Keep `N8N_ENCRYPTION_KEY` stable and backed up. Losing it can break stored credentials.
- Use persistent volumes `n8n_data` and `n8n_postgres_data`; restarting containers must not remove workflows or credentials.
- Upgrade n8n only by explicitly changing `N8N_IMAGE_TAG` after checking n8n breaking changes.
- Keep `N8N_IMAGE_TAG` pinned; never deploy `latest` for production.
- Do not expose the n8n editor publicly without strong authentication and trusted admin access.
- Store Gemini, Discord, database, and webhook secrets only in n8n Credentials, untracked env, or a production secret manager.
- Run the smoke checklist in [N8N_RUNBOOK.md](../../docs/N8N_RUNBOOK.md) after deploy, restore, update, rollback, and credential rotation.
