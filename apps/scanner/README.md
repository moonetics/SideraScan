# SideraScan Scanner

Go/Fyne desktop scanner for SideraScan.

## Requirements

- Go 1.26+
- CGO enabled
- Windows amd64 development target

## Development

Generate Windows resources:

```powershell
go generate ./...
```

Run tests:

```powershell
go test ./...
```

Build development binary:

```powershell
go build -ldflags "-H=windowsgui" ./cmd/siderascan
```

Build internal release executable:

```powershell
powershell -ExecutionPolicy Bypass -File ./build/windows/release.ps1 -Version 0.1.0 -BuildMode internal
```

Release output is written to `dist/SideraScan.exe` with `dist/SideraScan.exe.sha256`.
The script embeds the SideraScan icon, Windows manifest, version metadata, and build variables.
Root binaries such as `siderascan.exe` are local development artifacts and are not release outputs.

Override API base URL for local testing:

```powershell
$env:SIDERASCAN_API_URL="http://localhost:4000"
go run ./cmd/siderascan
```

Preview local UI states without backend:

```powershell
$env:SIDERASCAN_DEMO_MODE="true"
go run ./cmd/siderascan
```

`go run` and plain `go build ./cmd/siderascan` may show a console during development. Use the `-H=windowsgui` build commands above for the GUI-only `.exe`.

## Checksum Verification

```powershell
$expected = (Get-Content .\dist\SideraScan.exe.sha256).Split(" ")[0]
$actual = (Get-FileHash .\dist\SideraScan.exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($expected -ne $actual) { throw "Checksum mismatch" }
```

## QA

Run automated scanner QA:

```powershell
go test ./...
go build ./cmd/siderascan
```

Manual QA and release review docs:

- [QA checklist](docs/QA_CHECKLIST.md)
- [Privacy review](docs/PRIVACY_REVIEW.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)
- [Known limitations](docs/KNOWN_LIMITATIONS.md)

The local automated checks cover mocked API behavior, payload safety, redaction, progress/module runner behavior, rule evaluator safety, and retry cache behavior. Windows 10/11, standard/admin comparison, SmartScreen reputation, and real web upload verification remain manual checklist items.

## Smoke Test

1. Start SideraScan API and web locally.
2. Generate a scanner key from the web dashboard.
3. Run the scanner with the API URL:

```powershell
$env:SIDERASCAN_API_URL="http://localhost:4000"
.\dist\SideraScan.exe
```

4. Enter the raw scanner key and click `Start Scan`.
5. Confirm the uploaded scan appears in `http://localhost:3000/scans`.

Large forensic scans use hybrid upload: scanner tries a single JSON upload first, then automatically falls back to core + section chunk upload if the payload is too large or the API returns `413`.

## Signing

Development and internal testing builds are unsigned and should be labeled `unsigned/internal`.
Production builds must use an HTTPS API URL. The release script rejects production builds without one:

```powershell
powershell -ExecutionPolicy Bypass -File ./build/windows/release.ps1 -Version 0.1.0 -BuildMode production -APIBaseURL https://api.example.com
```

Production builds should be signed with a code signing certificate and timestamped:

```powershell
signtool sign /fd SHA256 /tr <timestamp-url> /td SHA256 /a .\dist\SideraScan.exe
```

After signing, regenerate or publish a post-signing checksum if the signed binary is the distributed artifact.
Do not sign or release builds that enable screenshot capture, stealth/background behavior, or persistence.

## Notes

- Scanner builds target Windows amd64 for the MVP.
- GoReleaser can be added later for multi-arch release automation, changelog, and artifact publishing.
- Scanner keys, upload tokens, nonce values, passwords, and tokens are redacted from logs.
- Screenshot capture is not part of the scanner MVP.
