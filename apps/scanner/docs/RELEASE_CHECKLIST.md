# SideraScan Scanner Release Checklist

Use this checklist for every internal or production scanner release.

## Build Inputs

- Version is a SemVer value, for example `0.1.0`.
- Commit is known and clean enough for release notes.
- Backend minimum supported scanner version is documented.
- Release status is labeled `internal unsigned` or `production signed`.
- Production API URL is HTTPS.

## Build Commands

Internal unsigned build:

```powershell
go generate ./...
go test ./...
go build ./cmd/siderascan
powershell -ExecutionPolicy Bypass -File ./build/windows/release.ps1 -Version 0.1.0 -BuildMode internal
```

Production build requires an HTTPS API URL:

```powershell
powershell -ExecutionPolicy Bypass -File ./build/windows/release.ps1 -Version 0.1.0 -BuildMode production -APIBaseURL https://api.example.com
```

## Artifact Verification

- `dist/SideraScan.exe` exists.
- `dist/SideraScan.exe.sha256` exists.
- Checksum matches:

```powershell
$expected = (Get-Content .\dist\SideraScan.exe.sha256).Split(" ")[0]
$actual = (Get-FileHash .\dist\SideraScan.exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($expected -ne $actual) { throw "Checksum mismatch" }
```

- Windows Properties show:
  - ProductName: `SideraScan`
  - FileDescription: `SideraScan Scanner`
  - CompanyName: `SideraLabs`
  - ProductVersion: release version
  - FileVersion: release file version
- Executable opens without a console window.

## Signing

Internal builds may remain unsigned and must be labeled `unsigned/internal`.
Production builds must be signed and timestamped:

```powershell
signtool sign /fd SHA256 /tr <timestamp-url> /td SHA256 /a .\dist\SideraScan.exe
```

After signing, regenerate or publish checksum for the exact signed executable.

## Smoke Test

- Start API, web, and PostgreSQL.
- Generate a scanner key from web.
- Run `dist/SideraScan.exe`.
- Validate key, approve consent, start scan.
- Confirm upload completes.
- Confirm scan appears in web `/scans`.
- Open scan detail and verify overview, modules, process timeline, custom detections, and Roblox sections where applicable.
- Test blocked version by generating a key that excludes the current scanner version.

## Security and Privacy Gate

Release is blocked if any item is true:

- Production build uses non-HTTPS remote API URL.
- Scanner collects screenshots, clipboard, browser cookies/history, passwords, file contents, full memory, or broad disk listing.
- Raw scanner key, upload token, nonce, MachineGuid, serial number, or private user path appears in logs, nested payload metadata, audit log, telemetry, or cache metadata.
- Scanner hides itself, adds persistence, starts in background, or auto-elevates.
- Checksum is missing or does not match.

## Release Notes

Release notes must include:

- Scanner version.
- Commit.
- Build time.
- Build mode.
- Checksum.
- Signing status.
- Minimum backend supported version.
- Known limitations link.
