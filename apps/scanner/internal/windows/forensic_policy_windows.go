//go:build windows

package windows

import (
	"path/filepath"
	"strings"
)

func policyIsDefenderUpdateArtifact(name string, pathValue string) bool {
	value := strings.ToLower(name + " " + pathValue)
	return strings.Contains(value, "am_delta") ||
		strings.Contains(value, "am_engine") ||
		strings.Contains(value, "mpsigstub") ||
		strings.Contains(value, "defender platform") ||
		strings.Contains(value, `\windows defender\`) ||
		strings.Contains(value, `\microsoft\windows defender\`)
}

func policyIsOfficialRobloxPath(pathValue string) bool {
	lower := strings.ToLower(strings.ReplaceAll(pathValue, "/", `\`))
	return strings.Contains(lower, `\appdata\local\roblox\versions\`) ||
		strings.Contains(lower, `\users\***\appdata\local\roblox\versions\`)
}

func policyIsCommonWindowsDLL(name string, pathValue string, publisher string, signer string) bool {
	lowerName := strings.ToLower(filepath.Base(name))
	lowerPath := strings.ToLower(strings.ReplaceAll(pathValue, "/", `\`))
	vendor := strings.ToLower(publisher + " " + signer)
	commonDLLs := map[string]bool{
		"advapi32.dll": true, "bcrypt.dll": true, "cfgmgr32.dll": true, "clbcatq.dll": true,
		"combase.dll": true, "crypt32.dll": true, "gdi32.dll": true, "gdi32full.dll": true,
		"imm32.dll": true, "kernel32.dll": true, "kernelbase.dll": true, "msvcp_win.dll": true,
		"ntdll.dll": true, "ole32.dll": true, "rpcrt4.dll": true, "sechost.dll": true,
		"shell32.dll": true, "shlwapi.dll": true, "ucrtbase.dll": true, "user32.dll": true,
		"userenv.dll": true, "win32u.dll": true, "winhttp.dll": true, "ws2_32.dll": true,
	}
	if commonDLLs[lowerName] {
		return true
	}
	return strings.HasPrefix(lowerPath, `c:\windows\system32\`) &&
		strings.Contains(vendor, "microsoft") &&
		strings.HasSuffix(lowerName, ".dll")
}

func policyIsKnownVendorArtifact(name string, pathValue string, publisher string, signer string) bool {
	value := strings.ToLower(name + " " + pathValue + " " + publisher + " " + signer)
	for _, marker := range []string{
		"microsoft", "intel", "realtek", "nvidia", "advanced micro devices", " amd ",
		"google drive", "google\\drivefs", "docker desktop", "dockerdesktop", "microsoft visual studio code",
		"\\microsoft vs code\\", "\\program files\\nodejs\\", "discord", "steam",
		"obs studio", "rivatuner", "msi afterburner", "overwolf", "browser", "chrome",
		"edge", "mozilla", "roblox corporation", "siderascan.exe",
	} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func policyIsKnownBenignInstaller(name string, pathValue string) bool {
	value := strings.ToLower(name + " " + pathValue)
	for _, marker := range []string{
		"discordsetup.exe",
		"docker desktop installer.exe",
		"codex installer",
		"robloxplayerinstaller",
		"robloxstudioinstaller",
		"\\temp\\roblox\\",
		"chrome setup", "chromesetup.exe",
		"firefox installer", "microsoftedgeupdate",
		"vc_redist", "vcredist",
	} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func policyIsKnownInstallerTempComponent(name string, pathValue string) bool {
	value := strings.ToLower(name + " " + pathValue)
	if !strings.Contains(value, `\temp\`) {
		return false
	}
	for _, marker := range []string{
		`\nst`, "nsexec.dll", "nsis7zu.dll", "nsprocess.dll", "nsduiskin.dll",
		"bgworker.dll", "hxcutils.dll", "system.dll", "uninst.exe",
		`\temp\roblox\robloxstudioinstaller.exe`,
	} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func policyIsNormalPersistenceDefault(kind string, name string, command string, pathValue string, location string) bool {
	kind = strings.ToLower(kind)
	name = strings.ToLower(strings.TrimSpace(name))
	value := strings.ToLower(command + " " + pathValue + " " + location)
	switch kind {
	case "winlogon":
		defaults := map[string]string{
			"shell":                 "explorer.exe",
			"userinit":              "userinit.exe",
			"vmApplet":              "systempropertiesperformance.exe",
			"shellappruntime":       "shellappruntime.exe",
			"shellinfrastructure":   "sihost.exe",
			"autologonsid":          "s-1-5-",
			"cachedlogonscount":     "",
			"defaultusername":       "",
			"reportbootok":          "",
			"debugservercommand":    "",
			"precreateknownfolders": "",
		}
		for key, expected := range defaults {
			if strings.EqualFold(name, key) && strings.Contains(value, strings.ToLower(expected)) {
				return true
			}
		}
	case "known_dlls":
		return !strings.Contains(value, `\users\`) && !strings.Contains(value, `\appdata\`) && !strings.Contains(value, `\temp\`)
	case "shell_extension":
		return strings.TrimSpace(command) == "" || strings.HasPrefix(name, "{")
	case "appinit_dlls":
		lowerName := strings.ToLower(name)
		if lowerName == "naturalinputhandler" ||
			lowerName == "iconservicelib" ||
			lowerName == "mnmsrvc" ||
			strings.Contains(value, "ninput.dll") ||
			strings.Contains(value, "iconcodecservice.dll") {
			return true
		}
		return strings.TrimSpace(command) == ""
	}
	return false
}

func policyStrongSignalCount(flags []string, signatureStatus string) int {
	seen := map[string]bool{}
	for _, flag := range flags {
		lower := strings.ToLower(flag)
		if strings.HasPrefix(lower, "defender_exclusion") ||
			strings.HasPrefix(lower, "hosts_blocks_") {
			seen[lower] = true
			continue
		}
		switch lower {
		case "temp_path", "appdata_path", "localappdata_path", "downloads_path", "discord_or_telegram_path",
			"windows_like_name_outside_windows", "unsigned_user_writable_path", "missing_file",
			"ifeo_debugger", "appinit_dlls", "winlogon_override", "known_dll_user_path",
			"driver_mapper_keyword", "powershell_encoded_command", "powershell_download_execute",
			"powershell_invoke_expression", "path_deleted_or_missing", "hosts_blocks_microsoft",
			"hosts_blocks_windowsupdate", "hosts_blocks_defender", "defender_exclusion",
			"defender_disabled", "protection_reduced":
			seen[strings.ToLower(flag)] = true
		}
	}
	if strings.EqualFold(signatureStatus, "unsigned") {
		seen["unsigned_signature"] = true
	}
	return len(seen)
}

func policyShouldCreateFinding(status string, severity string, flags []string, signatureStatus string) bool {
	status = strings.ToLower(status)
	severity = strings.ToUpper(severity)
	if severity == "SEVERE" || severity == "CRITICAL" || status == "flagged" {
		return true
	}
	if status == "suspicious" {
		return policyStrongSignalCount(flags, signatureStatus) >= 1
	}
	if severity == "WARNING" || status == "review" || status == "missing_file" {
		return policyStrongSignalCount(flags, signatureStatus) >= 2
	}
	return false
}

func policyReviewSeverity(status string) string {
	switch strings.ToLower(status) {
	case "suspicious", "flagged", "missing_file":
		return "WARNING"
	default:
		return "INFO"
	}
}

func policyCleanReviewTitle(value string) string {
	value = strings.TrimSpace(value)
	for _, prefix := range []string{"AF-3 review item: ", "AF-4 review item: ", "AF-5 review item: ", "AF-6 review item: ", "AF-7 review item: "} {
		value = strings.TrimPrefix(value, prefix)
	}
	return value
}
