# SideraScan Production Deployment

## Target

Production awal ditargetkan ke satu Linux VPS dengan Docker Compose:

- reverse proxy HTTPS
- `apps/api` sebagai backend NestJS
- `apps/web` sebagai Next.js dashboard
- PostgreSQL untuk SideraScan
- n8n self-hosted untuk AI review dan alert workflow

## Required Secrets

Semua secret production harus unik, panjang minimal 32 karakter, dan tidak memakai nilai development:

- `AUTH_SECRET`
- `SCANNER_KEY_HASH_SECRET`
- `SCANNER_UPLOAD_TOKEN_SECRET`
- `N8N_WEBHOOK_SECRET`
- `DATABASE_URL`
- `SEED_SUPER_ADMIN_PASSWORD`

## Environment Checklist

Backend:

- `NODE_ENV=production`
- `DATABASE_URL=postgresql://...`
- `WEB_ORIGIN=https://app.siderascan.com`
- `APP_DASHBOARD_URL=https://app.siderascan.com`
- `N8N_WEBHOOK_ENABLED=true`
- `N8N_SCAN_COMPLETED_WEBHOOK_URL=https://n8n.siderascan.com/webhook/siderascan-scan-completed`
- `N8N_ALERT_WEBHOOK_ENABLED=true`
- `N8N_ALERT_WEBHOOK_URL=https://n8n.siderascan.com/webhook/siderascan-security-alert`

Frontend:

- `NEXT_PUBLIC_API_URL=https://api.siderascan.com`

Retention defaults:

- scan results: 90 days
- findings/evidence: 90 days
- screenshots: 30 days
- detection samples: 7 days
- monitoring events: 30 days
- security events: 180 days
- audit logs: 365 days

## Deployment Flow

1. Provision Linux VPS and point DNS records:
   - `app.siderascan.com`
   - `api.siderascan.com`
   - `n8n.siderascan.com`
2. Install Docker Engine and Docker Compose plugin.
3. Create production `.env` files on the server only.
4. Start PostgreSQL and n8n first.
5. Run Prisma migration against production database.
6. Run seed once for the first Super Admin.
7. Start API and Web containers.
8. Verify:
   - `GET https://api.siderascan.com/health`
   - `GET https://api.siderascan.com/health/ready`
   - login at `https://app.siderascan.com/login`
   - n8n editor at `https://n8n.siderascan.com`
9. Configure n8n workflows for `scan.completed` and `security.alert`.
10. Run a scanner key validation and dummy scan upload test.

## Backup Plan

PostgreSQL backup:

```bash
pg_dump "$DATABASE_URL" > "siderascan-$(date +%F).sql"
```

Recommended production policy:

- daily database backup
- encrypt backup files before moving off-server
- keep at least 7 daily backups and 4 weekly backups
- test restore monthly on a staging database

n8n backup:

- back up n8n PostgreSQL database
- back up n8n persistent volume
- export workflows after major changes

## Rollback Plan

1. Keep the previous Docker image tag for API and Web.
2. If deployment fails before migration, switch back to previous tags.
3. If migration was applied, restore the latest verified database backup before switching back.
4. Confirm `/health/ready` and login after rollback.

## Security Review Checklist

- HTTPS is required for web, API, scanner endpoints, and n8n.
- Reverse proxy request limit should match API scanner upload policy, for example `client_max_body_size 30m`; large forensic scans still fall back to chunked section upload.
- Cookies are httpOnly and secure in production.
- CORS `WEB_ORIGIN` is production dashboard URL only.
- There is no public register route.
- Dashboard passwords use argon2id.
- Scanner keys are stored as HMAC hashes only.
- Upload tokens and nonce values are stored as hashes only.
- n8n callbacks require timestamped HMAC signature.
- Export reports are redacted.
- Audit logs and security events do not contain raw scanner key, upload token, nonce, password, MachineGuid, hardware serial, full HWID hash, screenshot binary, or unmasked private paths.
- Database user should use least required privileges for the application.
- Production backups are encrypted and access-controlled.
