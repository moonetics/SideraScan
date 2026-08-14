//go:build windows

package windows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/StackExchange/wmi"
	"github.com/shirou/gopsutil/v4/host"
	gopsnet "github.com/shirou/gopsutil/v4/net"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/moonetics/SideraScan/apps/scanner/internal/fingerprint"
	"github.com/moonetics/SideraScan/apps/scanner/internal/privacy"
)

type computerSystem struct {
	Manufacturer string
	Model        string
}

type baseBoard struct {
	Manufacturer string
	Product      string
}

type processor struct {
	Name string
}

type videoController struct {
	Name string
}

type diskDrive struct {
	Model string
}

func collectSnapshot(ctx context.Context, options CollectOptions) Snapshot {
	finishedAt := options.FinishedAt
	if finishedAt.IsZero() {
		finishedAt = time.Now().UTC()
	}
	startedAt := options.StartedAt
	if startedAt.IsZero() {
		startedAt = finishedAt
	}
	duration := finishedAt.Sub(startedAt)
	if duration < 0 {
		duration = 0
	}

	partials := []string{}
	hostInfo, err := host.InfoWithContext(ctx)
	if err != nil {
		partials = append(partials, "host_info")
	}

	registryInfo, err := collectRegistryInfo()
	if err != nil {
		partials = append(partials, "registry")
	}

	wmiInfo, err := collectWMIInfo()
	if err != nil {
		partials = append(partials, "wmi")
	}

	networkType, err := activeConnectionType(ctx)
	if err != nil {
		partials = append(partials, "network_adapter")
		networkType = "Unknown"
	}

	recycleBinActivity, err := recycleBinLastActivity()
	if err != nil {
		partials = append(partials, "recycle_bin")
	}

	runAsAdmin := isRunAsAdmin()
	vmResult := detectVM(hostInfo, wmiInfo)
	osName := displayOSName(hostInfo, registryInfo)
	bootTime := bootTimeValue(hostInfo)
	installDate := registryInfo.installDate
	signals := fingerprintSignals(registryInfo, wmiInfo)
	fp := fingerprint.Build(signals)

	overview := privacy.RedactMap(map[string]any{
		"scanSessionId":      options.ScanSessionID,
		"os":                 osName,
		"arch":               runtime.GOARCH,
		"vm":                 yesNoUnknown(vmResult.IsVM, vmResult.Known),
		"vmVendor":           vmResult.Vendor,
		"connectionType":     networkType,
		"country":            "Unknown",
		"installation":       formatOptionalTime(installDate),
		"recycleBin":         formatOptionalTime(recycleBinActivity),
		"bootTime":           formatOptionalTime(bootTime),
		"computerStartedAt":  formatOptionalTime(bootTime),
		"scanSpeed":          formatDuration(duration),
		"date":               finishedAt.UTC().Format(time.RFC3339),
		"runAsAdmin":         runAsAdmin,
		"collectorPartial":   len(partials) > 0,
		"collectorErrorKeys": partials,
	})

	systemIdentity := privacy.RedactMap(map[string]any{
		"os":                           osName,
		"platform":                     hostString(hostInfo, func(info *host.InfoStat) string { return info.Platform }),
		"platformVersion":              hostString(hostInfo, func(info *host.InfoStat) string { return info.PlatformVersion }),
		"kernelVersion":                hostString(hostInfo, func(info *host.InfoStat) string { return info.KernelVersion }),
		"kernelArch":                   hostString(hostInfo, func(info *host.InfoStat) string { return info.KernelArch }),
		"windowsBuild":                 registryInfo.buildNumber,
		"displayVersion":               registryInfo.displayVersion,
		"architecture":                 runtime.GOARCH,
		"hostnameHash":                 hostHash(hostInfo),
		"runAsAdmin":                   runAsAdmin,
		"vm":                           yesNoUnknown(vmResult.IsVM, vmResult.Known),
		"vmVendor":                     vmResult.Vendor,
		"vmReason":                     vmResult.Reason,
		"deviceFingerprintSignalsUsed": fp.SignalsUsed,
	})

	networkSnapshot := privacy.RedactMap(map[string]any{
		"connectionType": networkType,
		"country":        "Unknown",
	})

	integrity := privacy.RedactMap(map[string]any{
		"runAsAdmin": runAsAdmin,
		"permission": permissionText(runAsAdmin),
		"deviceFingerprint": map[string]any{
			"version":     fp.Fingerprint.Version,
			"confidence":  fp.Fingerprint.Confidence,
			"signalsUsed": fp.SignalsUsed,
		},
		"collectorPartial":   len(partials) > 0,
		"collectorErrorKeys": partials,
	})

	return Snapshot{
		Overview:          overview,
		SystemIdentity:    systemIdentity,
		NetworkSnapshot:   networkSnapshot,
		Integrity:         integrity,
		DeviceFingerprint: &fp.Fingerprint,
		PartialErrors:     partials,
	}
}

type registryInfo struct {
	machineGuid    string
	productName    string
	buildNumber    string
	displayVersion string
	installDate    time.Time
}

func collectRegistryInfo() (registryInfo, error) {
	info := registryInfo{}
	var errs []string

	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE); err == nil {
		defer key.Close()
		info.machineGuid, _, _ = key.GetStringValue("MachineGuid")
	} else {
		errs = append(errs, err.Error())
	}

	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		defer key.Close()
		info.productName, _, _ = key.GetStringValue("ProductName")
		info.buildNumber, _, _ = key.GetStringValue("CurrentBuildNumber")
		info.displayVersion, _, _ = key.GetStringValue("DisplayVersion")
		if installDate, _, err := key.GetIntegerValue("InstallDate"); err == nil && installDate > 0 {
			info.installDate = time.Unix(int64(installDate), 0).UTC()
		}
	} else {
		errs = append(errs, err.Error())
	}

	if len(errs) > 0 {
		return info, errors.New(strings.Join(errs, "; "))
	}

	return info, nil
}

type wmiInfo struct {
	computerSystems []computerSystem
	baseBoards      []baseBoard
	processors      []processor
	videoCards      []videoController
	disks           []diskDrive
}

func collectWMIInfo() (wmiInfo, error) {
	info := wmiInfo{}
	errs := []string{}

	if err := wmi.Query("SELECT Manufacturer, Model FROM Win32_ComputerSystem", &info.computerSystems); err != nil {
		errs = append(errs, "computer_system")
	}
	if err := wmi.Query("SELECT Manufacturer, Product FROM Win32_BaseBoard", &info.baseBoards); err != nil {
		errs = append(errs, "base_board")
	}
	if err := wmi.Query("SELECT Name FROM Win32_Processor", &info.processors); err != nil {
		errs = append(errs, "processor")
	}
	if err := wmi.Query("SELECT Name FROM Win32_VideoController", &info.videoCards); err != nil {
		errs = append(errs, "video")
	}
	if err := wmi.Query("SELECT Model FROM Win32_DiskDrive", &info.disks); err != nil {
		errs = append(errs, "disk")
	}

	if len(errs) > 0 {
		return info, errors.New(strings.Join(errs, "; "))
	}

	return info, nil
}

type vmResult struct {
	IsVM   bool
	Known  bool
	Vendor string
	Reason string
}

func detectVM(hostInfo *host.InfoStat, wmiInfo wmiInfo) vmResult {
	candidates := []string{}
	if hostInfo != nil {
		candidates = append(candidates, hostInfo.VirtualizationSystem, hostInfo.VirtualizationRole)
	}
	for _, item := range wmiInfo.computerSystems {
		candidates = append(candidates, item.Manufacturer, item.Model)
	}

	joined := strings.ToLower(strings.Join(candidates, " "))
	vendors := map[string]string{
		"vmware":       "VMware",
		"virtualbox":   "VirtualBox",
		"qemu":         "QEMU",
		"kvm":          "KVM",
		"hyper-v":      "Hyper-V",
		"hyperv":       "Hyper-V",
		"parallels":    "Parallels",
		"xen":          "Xen",
		"virtual":      "Virtualized",
		"bhyve":        "bhyve",
		"openstack":    "OpenStack",
		"bochs":        "Bochs",
		"innotek gmbh": "VirtualBox",
	}

	for needle, vendor := range vendors {
		if strings.Contains(joined, needle) {
			return vmResult{IsVM: true, Known: true, Vendor: vendor, Reason: "hardware_model_indicator"}
		}
	}

	if strings.TrimSpace(joined) == "" {
		return vmResult{Known: false, Vendor: "Unknown", Reason: "insufficient_data"}
	}

	return vmResult{IsVM: false, Known: true, Vendor: "None", Reason: "no_vm_indicator"}
}

func activeConnectionType(ctx context.Context) (string, error) {
	interfaces, err := gopsnet.InterfacesWithContext(ctx)
	if err != nil {
		return "Unknown", err
	}

	for _, iface := range interfaces {
		if !hasFlag(iface.Flags, "up") || hasFlag(iface.Flags, "loopback") {
			continue
		}
		name := strings.ToLower(iface.Name + " " + iface.HardwareAddr)
		switch {
		case strings.Contains(name, "wi-fi"), strings.Contains(name, "wifi"), strings.Contains(name, "wlan"), strings.Contains(name, "wireless"):
			return "Wi-Fi", nil
		case strings.Contains(name, "ethernet"), strings.Contains(name, "realtek"), strings.Contains(name, "intel"):
			return "Ethernet", nil
		default:
			return "Network Adapter", nil
		}
	}

	return "Unknown", nil
}

func hasFlag(flags []string, flag string) bool {
	for _, item := range flags {
		if strings.EqualFold(item, flag) {
			return true
		}
	}
	return false
}

func recycleBinLastActivity() (time.Time, error) {
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = `C:`
	}
	root := filepath.Join(systemDrive+`\`, "$Recycle.Bin")
	newest := time.Time{}
	visited := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		visited++
		if visited > 300 {
			return filepath.SkipAll
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime().UTC()
		}
		return nil
	})
	if err != nil {
		return time.Time{}, err
	}

	return newest, nil
}

func isRunAsAdmin() bool {
	token := windows.GetCurrentProcessToken()
	return token.IsElevated()
}

func fingerprintSignals(registryInfo registryInfo, wmiInfo wmiInfo) []fingerprint.Signal {
	signals := []fingerprint.Signal{
		{Name: "machine_guid", Value: registryInfo.machineGuid},
		{Name: "os_install_date", Value: formatOptionalTime(registryInfo.installDate)},
	}

	if len(wmiInfo.baseBoards) > 0 {
		signals = append(signals, fingerprint.Signal{Name: "motherboard_manufacturer", Value: wmiInfo.baseBoards[0].Manufacturer})
		signals = append(signals, fingerprint.Signal{Name: "motherboard_model", Value: wmiInfo.baseBoards[0].Product})
	}
	if len(wmiInfo.disks) > 0 {
		signals = append(signals, fingerprint.Signal{Name: "disk_model", Value: wmiInfo.disks[0].Model})
	}
	if len(wmiInfo.processors) > 0 {
		signals = append(signals, fingerprint.Signal{Name: "cpu_name", Value: wmiInfo.processors[0].Name})
	}
	if len(wmiInfo.videoCards) > 0 {
		signals = append(signals, fingerprint.Signal{Name: "gpu_name", Value: wmiInfo.videoCards[0].Name})
	}

	return signals
}

func displayOSName(hostInfo *host.InfoStat, registryInfo registryInfo) string {
	if registryInfo.productName != "" {
		return registryInfo.productName
	}
	if hostInfo != nil && hostInfo.Platform != "" {
		return hostInfo.Platform
	}
	return "Windows"
}

func bootTimeValue(hostInfo *host.InfoStat) time.Time {
	if hostInfo == nil || hostInfo.BootTime == 0 {
		return time.Time{}
	}
	return time.Unix(int64(hostInfo.BootTime), 0).UTC()
}

func hostHash(hostInfo *host.InfoStat) string {
	if hostInfo == nil || strings.TrimSpace(hostInfo.Hostname) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(hostInfo.Hostname))))
	return hex.EncodeToString(sum[:])
}

func hostString(hostInfo *host.InfoStat, read func(*host.InfoStat) string) string {
	if hostInfo == nil {
		return ""
	}
	return read(hostInfo)
}

func yesNoUnknown(value bool, known bool) string {
	if !known {
		return "Unknown"
	}
	if value {
		return "Yes"
	}
	return "No"
}

func permissionText(admin bool) string {
	if admin {
		return "administrator"
	}
	return "user_limited"
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return "Unknown"
	}
	return value.UTC().Format(time.RFC3339)
}

func formatDuration(duration time.Duration) string {
	seconds := int(duration.Round(time.Second).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Sprintf("%ds", seconds)
}
