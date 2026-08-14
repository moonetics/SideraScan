# SideraScan

SideraScan is a consent-based Windows scanner and web dashboard for reviewing Roblox-related scan results.

## Development

### Requirements

- Node.js 22+
- npm 11+
- Docker Desktop for local PostgreSQL

### Setup

Install dependencies:

```powershell
npm install
```

Copy the environment examples:

```powershell
Copy-Item .env.example .env
Copy-Item apps/api/.env.example apps/api/.env
Copy-Item apps/web/.env.example apps/web/.env.local
```

Start local PostgreSQL with Docker:

```powershell
npm run db:up
docker compose ps
```

Generate Prisma client:

```powershell
npm run prisma:generate
```

Run migrations:

```powershell
npm run prisma:migrate
```

Seed the first Super Admin:

```powershell
npm run prisma:seed
```

Reset the local development database if needed:

```powershell
npm run db:reset
npm run db:up
npm run prisma:migrate
npm run prisma:seed
```

### Run

API:

```powershell
npm run dev:api
```

Web:

```powershell
npm run dev:web
```

Validate the API health endpoint:

```powershell
Invoke-RestMethod http://localhost:4000/health
```

Expected response when Docker PostgreSQL is healthy:

```json
{
  "status": "ok",
  "service": "api",
  "database": "ok"
}
```

The web app runs at `http://localhost:3000` and reads API health from `NEXT_PUBLIC_API_URL`.

### Validation and E2E

Run static validation:

```powershell
npm run lint
npm run typecheck
npm run build
```

Run browser E2E tests with Playwright:

```powershell
npm run e2e
```

Playwright starts `apps/api` and `apps/web` automatically when ports `4000` and `3000` are free. If you already have dev servers running in VS Code, stop them first for the cleanest E2E run, or make sure they are using the latest code.

Open the Playwright HTML report after a run:

```powershell
npm run e2e:report
```

### Auth

The dashboard has no public register page or register API route. The first user is seeded from `SEED_SUPER_ADMIN_*` env values.

Default development credential from `.env.example`:

- Identifier: `admin@example.com` or `superadmin`
- Password: `ChangeMe12345!`

Validate the login flow after starting the API:

```powershell
$login = Invoke-WebRequest http://localhost:4000/auth/login -Method POST -ContentType "application/json" -Body '{"identifier":"admin@example.com","password":"ChangeMe12345!"}' -SessionVariable session
Invoke-RestMethod http://localhost:4000/auth/me -WebSession $session
Invoke-RestMethod http://localhost:4000/auth/logout -Method POST -ContentType "application/json" -Body '{}' -WebSession $session
```

### Accounts and Roles

Phase 2 adds account isolation and admin-managed users. There is still no public register route.

Protected API endpoints:

- `POST /accounts`
- `GET /accounts`
- `GET /accounts/:id`
- `PATCH /accounts/:id`
- `POST /accounts/:id/suspend`
- `POST /accounts/:id/users`
- `POST /users`
- `GET /users`
- `PATCH /users/:id`
- `POST /users/:id/disable`

The accounts UI is available at:

```text
http://localhost:3000/accounts
```

Super Admin can create accounts, create users, assign account roles, and suspend accounts. Account Owner, Moderator, and Viewer users only see assigned accounts.

### Scanner Keys

Phase 3 adds scanner key management. Raw scanner keys are displayed only once after create/rotate and are stored as HMAC hashes in PostgreSQL.

Protected API endpoints:

- `GET /scanner-keys`
- `POST /accounts/:id/scanner-keys`
- `GET /accounts/:id/scanner-keys`
- `POST /scanner-keys/:id/rotate`
- `POST /scanner-keys/:id/revoke`

The scanner key UI is available at:

```text
http://localhost:3000/scanner-keys
```

### Scanner Sessions and Dummy Results

Phase 4 adds scanner key validation, short-lived upload sessions, dummy scan result ingestion, and scan list/detail pages.

Public scanner endpoints:

- `POST /scanner/validate-key`
- `POST /scanner/sessions/:id/results`
- `POST /scanner/sessions/:id/results/core`
- `POST /scanner/sessions/:id/results/section`
- `POST /scanner/sessions/:id/complete`

Scanner upload uses a hybrid strategy. Normal scans use single JSON upload. Large forensic scans automatically fall back to chunked section upload so the core scan is saved first, then large sections are uploaded one by one. Production API body limit defaults to `API_BODY_LIMIT_BYTES=31457280` (30 MB); reverse proxies should use a matching limit such as Nginx `client_max_body_size 30m`.

Protected dashboard endpoints:

- `GET /scans`
- `GET /scans/:id`

The scan UI is available at:

```text
http://localhost:3000/scans
```

### Production Polish

Phase 11 adds redacted scan report export and retention settings dry-run.

Protected API endpoints:

- `GET /scans/:id/export?format=html|json`
- `GET /settings/retention`
- `PATCH /settings/retention`
- `POST /settings/retention/dry-run`

The settings UI is available to Super Admin at:

```text
http://localhost:3000/settings
```

Production deployment notes are in `docs/PRODUCTION_DEPLOYMENT.md`.
