# Executor Intelligence Feed

SideraScan can sync a community-maintained Roblox executor status feed and turn
Windows executor names into managed scanner rules. This is an advisory
intelligence source, not proof by itself.

## Sources

- Primary: `https://executors.online/api/executors`
- Fallback: `https://weao.xyz/api/status/exploits`
- Required WEAO user agent: `WEAO-3PService`

Executors.Online asks consumers to credit the source, cache responses, avoid
hammering the API, and handle non-200 responses gracefully. The default
SideraScan cache TTL is 24 hours.

## Stored Data

The backend stores only safe feed metadata:

- executor title and normalized slug
- platform and executor type
- detected/update status
- version/update text when provided
- source name/URL and attribution
- generated managed rule ids

SideraScan does not download, store, execute, or hash executor binaries from the
feed. It does not store screenshots, logos, download links, Discord links, or raw
website content.

## Detection Policy

Generated rules are global, managed, read-only detection rules. They are sent to
the scanner through `/scanner/config`, so the scanner does not need to be rebuilt
when the feed changes.

Name-only matches are emitted as `INFO` review context. A feed match can become
`WARNING` only when paired with supporting signals such as:

- executable under Temp, Downloads, AppData, Discord, or Telegram paths
- unsigned or untrusted signature
- Roblox process correlation
- persistence or Defender exclusion context
- downloaded, executed, or deleted artifact chain
- suspicious artifact flags from existing forensic modules

Executor intelligence never creates `SEVERE` by itself and never auto-bans.
Manual moderator review remains required.

## Operations

Super Admins can manage the feed from `/custom-detections`:

- view enabled state, attribution, last sync, and counts
- sync manually
- enable or disable generated intelligence rules
- preview Windows executor items

The API backend also runs a best-effort automatic sync loop when
`EXECUTOR_INTEL_AUTO_SYNC_ENABLED=true`. The production default interval is one
day:

```env
EXECUTOR_INTEL_AUTO_SYNC_ENABLED=true
EXECUTOR_INTEL_AUTO_SYNC_INTERVAL_SECONDS=86400
EXECUTOR_INTEL_SYNC_COOLDOWN_SECONDS=3600
```

This scheduler runs inside the API container on the single-VPS Docker Compose
deployment. A separate cron container is not required for the MVP. If the system
is scaled to multiple API replicas later, add a database advisory lock or move
the sync into a single worker/cron job to avoid duplicate external feed calls.

If the feed is unavailable, scanner config still works with cached generated
rules. If there is no cache, the backend returns normal scanner config without
executor intelligence rules.
