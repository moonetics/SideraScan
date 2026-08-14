# SideraScan Scanner QA Checklist

Use this checklist before sharing an internal scanner build.

## Automated Checks

Run from `apps/scanner`:

```powershell
go generate ./...
go test ./...
go build ./cmd/siderascan
powershell -ExecutionPolicy Bypass -File ./build/windows/release.ps1 -Version 0.1.0 -BuildMode internal
```

Verify:

- `dist/SideraScan.exe` exists.
- `dist/SideraScan.exe.sha256` exists.
- `Get-FileHash dist/SideraScan.exe -Algorithm SHA256` matches the checksum file.
- The release executable opens without a console window.
- Production release command rejects non-HTTPS remote API URLs.

## Windows Compatibility Matrix

Record pass/fail for each environment:

| Environment | Standard user | Administrator | Notes |
| --- | --- | --- | --- |
| Windows 10 amd64 | Pending | Pending | |
| Windows 11 amd64 | Pending | Pending | |

Standard user acceptance:

- App opens without UAC.
- Consent screen warns that some modules may be limited.
- Scan completes or uploads `PARTIAL` instead of crashing.

Administrator acceptance:

- App opens normally when started with Run as administrator.
- More privileged modules may collect additional metadata.
- No forced auto-elevation occurs.

## Scanner Key Scenarios

Use a local API/web environment.

- Valid key: validates, fetches config, shows consent, uploads scan, scan appears in `/scans`.
- Invalid key: shows user-friendly invalid key status and does not scan.
- Revoked key: shows revoked status and does not scan.
- Expired key: shows expired status and does not scan.
- Version blocked: shows scanner version blocked and does not scan.

## Network and Retry Scenarios

- No internet/API unavailable before validation: UI shows server unavailable/retryable status.
- API stops after consent before upload: failed upload screen appears with retry/discard controls.
- API restarts before upload token expiry: `Retry Upload` completes the scan.
- Upload token expires: retry is disabled or replaced by start-over flow.
- Failed upload cache: payload is DPAPI-protected when available and deleted after success/discard.

## Manual End-to-End Smoke Test

1. Start Docker Postgres, API, and web.
2. Login as Super Admin.
3. Create or use an account.
4. Generate a scanner key and copy the raw key once.
5. Run:

```powershell
$env:SIDERASCAN_API_URL="http://localhost:4000"
.\dist\SideraScan.exe
```

6. Enter the key, validate, approve consent, and start the scan.
7. Open `http://localhost:3000/scans`.
8. Confirm the scan detail shows overview, modules, process timeline, Roblox tabs where applicable, and indication log.

## AV and SmartScreen Notes

- Internal builds are unsigned and may show SmartScreen or antivirus reputation warnings.
- Unsigned/internal builds must not be presented as production-ready.
- Production release requires code signing with timestamping.
- Do not ask users to disable antivirus globally; collect the warning details and review signing/reputation instead.

## Release Gate

Before production distribution, complete the [release checklist](RELEASE_CHECKLIST.md), [privacy review](PRIVACY_REVIEW.md), and known limitations review.
