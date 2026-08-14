# SideraScan n8n Production Runbook

This runbook covers the production MVP n8n deployment for SideraScan on a single VPS with Docker Compose, dedicated n8n PostgreSQL, persistent volumes, and HTTPS reverse proxy.

## Production Gates

- Use a pinned n8n image tag through `N8N_IMAGE_TAG`; never deploy `latest`.
- Keep `n8n-postgres` private. It must not have public `ports`.
- Route public traffic through HTTPS reverse proxy to internal `n8n:5678`.
- Set `WEBHOOK_URL` to the public HTTPS n8n URL, for example `https://n8n.example.com/`.
- Restrict n8n editor access to trusted admins only. Do not expose a no-auth public editor.
- Back up `N8N_ENCRYPTION_KEY`; losing it can make stored credentials unreadable.
- Store real secrets only in untracked `infra/n8n/.env`, deployment secret manager, or n8n Credentials.

## Deploy

1. Copy the runtime env template:

   ```powershell
   Copy-Item infra/n8n/.env.example infra/n8n/.env
   ```

2. Fill production values in the untracked env:

   - `N8N_IMAGE_TAG`
   - `N8N_HOST`
   - `N8N_PROTOCOL=https`
   - `WEBHOOK_URL=https://<n8n-domain>/`
   - `N8N_ENCRYPTION_KEY`
   - `N8N_DB_PASSWORD`
   - `SIDERASCAN_WEBHOOK_SECRET`
   - AI provider credentials in n8n Credentials, not this file
   - optional Discord webhook only in env/secret manager

3. Validate Compose:

   ```powershell
   docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml config --quiet
   ```

4. Start n8n:

   ```powershell
   docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml up -d
   ```

5. Check status and logs:

   ```powershell
   docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml ps
   docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml logs -f n8n
   ```

## Reverse Proxy

Configure the reverse proxy to:

- terminate HTTPS for `n8n.<domain>`;
- forward requests to internal `n8n:5678`;
- preserve `Host`, `X-Forwarded-For`, `X-Forwarded-Proto`, and upgrade headers;
- redirect HTTP to HTTPS;
- keep the n8n PostgreSQL service unreachable from the public internet.

Production n8n env must match the public route:

```env
N8N_HOST=n8n.example.com
N8N_PROTOCOL=https
WEBHOOK_URL=https://n8n.example.com/
```

## Workflow Import and Restart Verification

Import or re-import these workflow templates after first deploy:

- `infra/n8n/workflows/siderascan-ai-review.workflow.json`
- `infra/n8n/workflows/siderascan-security-alert.workflow.json`

After restart or restore:

1. Open n8n editor through HTTPS.
2. Confirm both workflows are active.
3. Confirm Gemini credential is present and linked to the AI workflow.
4. Confirm the security alert workflow can read its runtime env/variables.
5. Trigger signed smoke tests for `scan.completed` and `security.alert`.

## Backup

Back up all of the following:

- n8n PostgreSQL database;
- `n8n_data` volume;
- production `infra/n8n/.env` or secret manager values;
- reverse proxy config;
- current workflow JSON exports.

Database backup:

```powershell
docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml exec n8n-postgres pg_dump -U n8n -d n8n > n8n-backup.sql
```

Volume backup example:

```powershell
docker run --rm -v siderascan-n8n_n8n_data:/data -v ${PWD}:/backup alpine tar czf /backup/n8n-data-backup.tgz -C /data .
```

Recommended retention:

- keep at least 7 daily backups;
- keep at least 4 weekly backups after production stabilizes;
- test restore before launch and after major n8n upgrades.

## Restore

1. Stop n8n:

   ```powershell
   docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml down
   ```

2. Restore `infra/n8n/.env` with the same `N8N_ENCRYPTION_KEY`.
3. Restore `n8n_data` volume from backup.
4. Start PostgreSQL, then restore database:

   ```powershell
   docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml up -d n8n-postgres
   docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml exec -T n8n-postgres psql -U n8n -d n8n < n8n-backup.sql
   ```

5. Start n8n:

   ```powershell
   docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml up -d
   ```

6. Run the restart verification checklist.

## Update and Rollback

Update:

1. Export workflows from n8n and back up database/volume.
2. Change `N8N_IMAGE_TAG` in untracked production env to the approved version.
3. Pull and recreate:

   ```powershell
   docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml pull n8n
   docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml up -d n8n
   ```

4. Run all smoke tests.

Rollback:

1. Set `N8N_IMAGE_TAG` back to the previous known-good tag.
2. Recreate n8n:

   ```powershell
   docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml up -d n8n
   ```

3. If workflows or credentials were modified by the failed upgrade, restore database and `n8n_data` from backup.

## Credential and Secret Rotation

- Rotate `SIDERASCAN_WEBHOOK_SECRET` in both SideraScan API env and n8n runtime env at the same maintenance window.
- Recreate n8n after env changes so runtime values refresh.
- Rotate Gemini/AI provider keys inside n8n Credentials.
- Rotate Discord webhook URL in runtime env/secret manager only.
- Never put real secrets in workflow JSON, README files, PRDs, screenshots, or issue comments.

## Smoke Checklist

Run these checks after deploy, restore, update, rollback, and credential rotation:

- `docker compose --env-file infra/n8n/.env -f infra/n8n/docker-compose.n8n.yml config --quiet`
- n8n editor opens through HTTPS.
- Workflows remain active after restart.
- Signed `scan.completed` returns accepted.
- AI Review workflow reaches `POST /scan-reviews`.
- Signed `security.alert` returns accepted.
- `HIGH` security alert sends Discord notification when enabled.
- Invalid signature is rejected.
- Stale timestamp is rejected.
- Duplicate idempotency key does not create duplicate review rows in SideraScan.
- SideraScan scan upload and complete still succeed when n8n is offline.

## Payload Safety Checklist

n8n workflows and alerts must not store or display:

- raw scanner key;
- upload token;
- nonce;
- raw HWID;
- MachineGuid;
- hardware serial;
- password;
- cookie;
- clipboard data;
- screenshot data;
- file content;
- private unmasked user paths.

Allowed data is limited to backend-generated redacted context, scan IDs, account IDs/names, finding/evidence IDs, device fingerprint prefix, dashboard URL, and capped sanitized metadata.
