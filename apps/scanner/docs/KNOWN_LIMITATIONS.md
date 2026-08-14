# SideraScan Scanner Known Limitations

## Collection Accuracy

- File logs are best-effort metadata, not a complete forensic timeline.
- Rename and move events are only shown when a safe source provides both old and new paths.
- Prefetch, WMI, registry, Defender, scheduled task, and service data may be unavailable or partial depending on Windows edition, permissions, policy, and system state.
- Process start time and parent process data are best-effort.

## Permissions

- Standard user mode is supported, but some modules may be limited.
- Scanner does not force UAC elevation.
- Administrator mode may improve visibility, but scan review must still consider false positives.

## Detection Limits

- Bloxstrap is not automatically severe.
- Custom detection string rules only scan approved scoped files.
- Scanner does not scan all process memory or all disk contents.
- Rule matches require moderator review and should not be treated as automatic proof.

## Privacy and Safety

- Screenshot capture is not included in the MVP.
- Browser history, cookies, passwords, clipboard data, and private file contents are not collected.
- Device fingerprint is hash-only and can change after reinstall, VM changes, or hardware changes.
- HWID match must not be the only evidence for enforcement.

## Release and Reputation

- Internal builds are unsigned and may trigger SmartScreen or antivirus warnings.
- Production release requires code signing certificate and timestamping.
- Code signing improves trust but does not replace QA, privacy review, or malware/AV review.
