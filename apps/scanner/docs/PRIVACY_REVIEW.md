# SideraScan Scanner Privacy Review

Use this checklist before internal or production distribution.

## Must Not Collect or Send

- Screenshot data.
- Browser history, browser cookies, or session data.
- Passwords, dashboard tokens, scanner keys in result payloads, or arbitrary credentials.
- Clipboard data.
- Full memory scan or process memory dump.
- Full disk scan or broad recursive listing outside approved scanner scopes.
- Raw `MachineGuid`.
- Raw hardware serial numbers.
- Raw upload token or nonce in nested payload metadata, telemetry, audit log, cache metadata, or logs.
- Private user paths without masking.
- File contents or sample bytes.

## Allowed MVP Data

- Scanner version, build mode, and safe technical telemetry.
- Process metadata and module durations.
- Masked paths such as `C:\Users\***\Downloads\tool.exe`.
- Hashes for approved executable/rule matches.
- Hashed device fingerprint only.
- Roblox/Bloxstrap metadata from approved folders.
- Retry count, upload duration, normalized error codes.
- `uploadToken` and `nonce` only as required top-level fields in scanner upload/complete API requests.

## Review Steps

- Run `go test ./...`.
- Inspect failed upload cache metadata and confirm it has no raw secrets.
- Confirm `%TEMP%\SideraScan\sessions\<scanSessionId>\payload.enc` is encrypted when DPAPI is available.
- Confirm cache is deleted after successful upload or discard.
- Search logs for scanner key, upload token, nonce, raw HWID, raw user paths, password, cookie, clipboard, and screenshot terms.
- Confirm UI text does not claim screenshot capture is available.
- Confirm scanner does not auto-start, hide itself, persist, or run in background after closing.
- Confirm production build mode refuses non-HTTPS remote API URLs.
- Confirm release notes include checksum, signing status, and minimum backend supported scanner version.

## Release Gate

A build fails privacy review if it includes screenshot capture, browser data collection, clipboard reading, memory scanning, raw HWID collection, raw private paths, or raw secrets in logs/cache/payload beyond the required top-level upload API fields.
