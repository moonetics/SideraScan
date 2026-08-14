# SideraScan Forensic False-Positive Tuning

SideraScan forensic output is advisory. It must help moderators review scan context, but it must not auto-ban or treat a single noisy artifact as proof.

## Severity Policy

- `INFO`: context only. Historical artifacts, benign vendor components, DNS/USB context, and normal Windows metadata live here by default.
- `REVIEW`: worth human attention in a table, but not enough to raise risk score by itself.
- `WARNING`: requires a strong signal or multiple supporting signals, such as suspicious path plus unsigned signature, Defender exclusion plus suspicious file, or downloaded/executed/deleted chain.
- `SEVERE`: reserved for high-confidence chains, explicit custom detections, HWID/manual marks, event log clearing near suspicious activity, or confirmed Defender detections with strong threat category.

## Known Benign Patterns

These should not become warning findings by default:

- Microsoft Defender update artifacts such as `AM_DELTA_PATCH`, `AM_ENGINE_PATCH`, platform update tools, and normal Defender churn.
- Official Roblox modules under `%LOCALAPPDATA%\Roblox\Versions\...` when no additional suspicious signal exists.
- Common Microsoft/System32 DLLs such as `cfgmgr32.dll`, `kernel32.dll`, `user32.dll`, `advapi32.dll`, `ntdll.dll`, and similar signed platform modules.
- Normal Bloxstrap installation/customization metadata. Bloxstrap is not severe by existence.
- Common signed vendor apps/drivers from Microsoft, Intel, Realtek, NVIDIA, AMD, Google Drive, Docker Desktop, VS Code, Discord, browsers, Steam, OBS, RivaTuner/MSI Afterburner, and Overwolf.
- Default Winlogon, KnownDLLs, Shell Extension, AppInit, and Userinit registry values.

## When Benign Becomes Suspicious

Benign names or paths can still be suspicious when context supports it:

- Official-looking filename outside expected vendor or Windows locations.
- Unsigned executable/DLL in a user-writable path.
- Persistence entry that points to Temp/AppData/Downloads or a missing binary.
- Defender exclusion that points at suspicious user-writable executable/script paths.
- Loaded DLL or process handle tied to Roblox plus suspicious path/signature/access rights.
- Historical artifact chain where the same target appears as downloaded, executed, and deleted.

## Detection Engineering Notes

This policy follows common detection-engineering practice:

- Sigma rules document `falsepositives`, `level`, and `scope`; SideraScan keeps context rows separate from warning findings.
- LOLBAS-style binaries are legitimate until command/context indicates abuse.
- Microsoft Sysmon image-load/network/driver data is high-volume and must be filtered.
- Sysinternals Autoruns shows many normal persistence locations; defaults are not findings.
- MITRE ATT&CK-style review should prefer behavior chains over single artifact names.

References used for this tuning pass:

- Sigma rule format: `falsepositives`, `fields`, and `level` are analyst context, not automatic verdicts. https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html
- Microsoft Sysmon: image-load and network/driver telemetry are high-volume and must be configured/tuned carefully. https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Microsoft Sysmon events: image-load events are useful but noisy and need filtering. https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events
- LOLBAS: legitimate Windows binaries/scripts/libraries can be abused, so context matters more than name alone. https://lolbas-project.github.io/
- MITRE ATT&CK detection strategies: behavior-chain detection combines multiple analytic signals. https://attack.mitre.org/detectionstrategies/

## Current MVP Limits

- No external reputation lookup is performed.
- No memory dump, process memory scan, browser history, cookies, passwords, clipboard, screenshots, chat content, or file content upload.
- Some artifacts are best-effort and may be missing without making a scan partial.
- Old timestamps are historical artifact timestamps, not proof that activity happened during the scan.
